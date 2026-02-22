package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"go.mongodb.org/mongo-driver/bson"
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

const MaxFailedAttempts = 5

// ==========================
// UTIL
// ==========================

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}


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



func recoverSafe(name string) {
	if r := recover(); r != nil {
		log.Println("Recovered panic in", name, ":", r)
	}
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
		if strings.Contains(host, ":") {
			h, _, _ := net.SplitHostPort(host)
			host = h
		}

		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			sendHTML(w)
			return
		}

		sub := strings.ToLower(parts[0])

		row, err := model.GetBySubdomain(sub)
		if err != nil || row.Status != 1 || row.IsBanned == 1 || row.IsConnected != 1 {
			sendHTML(w)
			return
		}

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

		r.RequestURI = ""
		r.Header.Set("Connection", "close")

		if err := r.Write(stream); err != nil {
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
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

	ln, err := net.Listen("tcp", ":7000")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Tunnel server listening on :7000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, model)
	}
}

func handleClient(conn net.Conn, model *models.SubDomainModel) {

	defer recoverSafe("HANDLE_CLIENT")
	defer conn.Close()

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	line, err := reader.ReadBytes('\n')
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Time{})

	var reg RegisterMsg
	if err := json.Unmarshal(line, &reg); err != nil {
		return
	}
	
	if reg.Type != "register" {
		return
	}

	sub := strings.ToLower(strings.TrimSpace(reg.Subdomain))
	if sub == "" {
		return
	}

	row, err := model.GetBySubdomain(sub)
	if err != nil || row.Status != 1 || row.IsBanned == 1 {
		return
	}

	clientHash := reg.Token

	if subtle.ConstantTimeCompare(
		[]byte(clientHash),
		[]byte(row.TokenHash),
	) != 1 {

		model.UpdateFailedAuth(sub)

		if row.FailedAuthCount+1 >= MaxFailedAttempts {
			model.UpdateByKey(sub, "is_banned", 1)
		}
		return
	}

	// 🔥 ATOMIC DB LOCK (Prevent Double Connect)
	sessionID := generateSessionID()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := model.Collection.UpdateOne(
		ctx,
		bson.M{
			"subdomain":    sub,
			"is_connected": 0,
		},
		bson.M{
			"$set": bson.M{
				"is_connected": 1,
				"session_id":   sessionID,
				"connected_at": time.Now(),
			},
		},
	)

	if err != nil || res.ModifiedCount == 0 {
		conn.Write([]byte(`{"error":"already_connected"}` + "\n"))
		return
	}

	// create yamux
	session, err := yamux.Server(&bufferedConn{Conn: conn, reader: reader}, nil)
	if err != nil {
		model.UpdateByKey(sub, "is_connected", 0)
		return
	}

	mu.Lock()
	sessions[sub] = session
	mu.Unlock()

	log.Println("Connected:", sub)

	<-session.CloseChan()

	// cleanup
	mu.Lock()
	delete(sessions, sub)
	mu.Unlock()

	model.Collection.UpdateOne(
		context.Background(),
		bson.M{"subdomain": sub},
		bson.M{
			"$set": bson.M{
				"is_connected": 0,
				"session_id":   "",
			},
		},
	)

	log.Println("Disconnected:", sub)
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
