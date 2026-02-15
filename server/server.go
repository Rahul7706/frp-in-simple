package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"server_frp/models"
)

type RegisterMsg struct {
	Type      string `json:"type"`
	Subdomain string `json:"subdomain"`
	Token     string `json:"token"`
}

var (
	mu       sync.RWMutex
	sessions = make(map[string]*yamux.Session)
)

// ==========================
// HTML ERROR RESPONSE
// ==========================
func sendHTML(w http.ResponseWriter) {
	defaultErrorResponse := `<!DOCTYPE html>
<html>
<head>
	<title>503 Service Unavailable</title>
	<style>
		body { background: #F1F1F1; }
		.box {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
			background: #FFF;
			padding: 8px 32px;
			box-shadow: 0px 0px 16px rgba(0,0,0,0.1);
			margin-top: 80px;
			font-weight: 300;
		}
		.box h1 { font-weight: 300; }
	</style>
</head>
<body>
	<div class="box">
		<h1>503 Service Unavailable</h1>
		<p>Sorry, the page you are looking for is currently unavailable.
		Please try again later.</p>
		<p align="right"><em>Powered by roboticx</em></p>
	</div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(503)
	w.Write([]byte(defaultErrorResponse))
}

// ==========================
// SAFE RECOVER
// ==========================
func recoverSafe(name string) {
	if r := recover(); r != nil {
		log.Println("Recovered panic in", name, ":", r)
	}
}

// ==========================
// TOKEN HASH (SHA256)
// ==========================
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ==========================
// MAIN
// ==========================
func main() {

	model, err := models.NewSubDomainModel()
	if err != nil {
		log.Fatal("DB model error:", err)
	}

	go startTunnelServer(model)
	startHTTPServer(model)
}

// ==========================
// HTTP SERVER
// ==========================
func startHTTPServer(model *models.SubDomainModel) {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		defer recoverSafe("HTTP_HANDLER")

		host := r.Host
		if host == "" {
			sendHTML(w)
			return
		}

		// remove port
		if strings.Contains(host, ":") {
			h, _, err := net.SplitHostPort(host)
			if err == nil {
				host = h
			} else {
				host = strings.Split(host, ":")[0]
			}
		}

		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			sendHTML(w)
			return
		}

		sub := strings.ToLower(parts[0])

		// DB check
		row, err := model.GetBySubdomain(sub)
		if err != nil {
			sendHTML(w)
			return
		}

		// status check
		if row.Status != 1 || row.IsBanned == 1 {
			sendHTML(w)
			return
		}

		// active session check
		mu.RLock()
		session := sessions[sub]
		mu.RUnlock()

		if session == nil || session.IsClosed() {
			sendHTML(w)
			return
		}

		stream, err := session.Open()
		if err != nil {
			sendHTML(w)
			return
		}
		defer stream.Close()

		// clone request
		reqClone := new(http.Request)
		*reqClone = *r
		reqClone.RequestURI = ""
		reqClone.Header.Set("Connection", "close")

		err = reqClone.Write(stream)
		if err != nil {
			sendHTML(w)
			return
		}

		// read response
		resp, err := http.ReadResponse(bufio.NewReader(stream), reqClone)
		if err != nil {
			sendHTML(w)
			return
		}
		defer resp.Body.Close()

		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	log.Println("HTTP server running on :4000")
	log.Fatal(http.ListenAndServe(":4000", nil))
}

// ==========================
// TUNNEL SERVER
// ==========================
func startTunnelServer(model *models.SubDomainModel) {

	defer recoverSafe("TUNNEL_SERVER")

	ln, err := net.Listen("tcp", ":7000")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Tunnel server listening on :7000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleClient(conn, model)
	}
}

func handleClient(conn net.Conn, model *models.SubDomainModel) {

	defer recoverSafe("HANDLE_CLIENT")
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// avoid client hanging forever
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	line, err := reader.ReadBytes('\n')
	if err != nil {
		log.Println("Failed to read register msg:", err)
		return
	}

	// after register remove deadline
	conn.SetReadDeadline(time.Time{})

	var reg RegisterMsg
	err = json.Unmarshal(line, &reg)
	if err != nil {
		log.Println("Invalid register JSON:", err)
		return
	}

	if reg.Type != "register" {
		log.Println("Invalid register type")
		return
	}

	sub := strings.ToLower(strings.TrimSpace(reg.Subdomain))
	if sub == "" {
		log.Println("Empty subdomain not allowed")
		return
	}

	// DB check
	row, err := model.GetBySubdomain(sub)
	if err != nil {
		log.Println("Subdomain not found:", sub)
		return
	}

	if row.Status != 1 {
		log.Println("Subdomain inactive:", sub)
		return
	}

	if row.IsBanned == 1 {
		log.Println("Subdomain banned:", sub)
		return
	}

	if reg.Token == "" {
		log.Println("Token empty")
		model.UpdateFailedAuth(sub)
		return
	}

	// HASH VERIFY
	clientHash := hashToken(reg.Token)
	if clientHash != row.TokenHash {
		log.Println("Invalid token for subdomain:", sub)
		model.UpdateFailedAuth(sub)
		return
	}

	// create yamux session
	session, err := yamux.Server(&bufferedConn{Conn: conn, reader: reader}, nil)
	if err != nil {
		log.Println("Yamux server error:", err)
		return
	}

	// store session
	mu.Lock()
	if old, ok := sessions[sub]; ok {
		old.Close()
	}
	sessions[sub] = session
	mu.Unlock()

	// update DB connected
	ip := conn.RemoteAddr().String()
	model.MarkConnected(sub, ip, "yamux-client")

	log.Println("Registered subdomain:", sub)

	<-session.CloseChan()

	// cleanup session
	mu.Lock()
	delete(sessions, sub)
	mu.Unlock()

	model.MarkDisconnected(sub)

	log.Println("Client disconnected:", sub)
}

// ==========================
// BUFFERED CONN
// ==========================
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}
