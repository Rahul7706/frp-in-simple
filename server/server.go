package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"
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

const AUTH_TOKEN = "secret123"

func main() {
	go startTunnelServer()
	startHTTPServer()
}

func startHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			http.Error(w, "No subdomain found", 404)
			return
		}

		sub := strings.ToLower("a")
		mu.RLock()
		session := sessions[sub]
		mu.RUnlock()

		if session == nil {
			http.Error(w, "No tunnel client for subdomain "+sub, 502)
			return
		}
		stream, err := session.Open()
		if err != nil {
			http.Error(w, "Tunnel stream open failed", 502)
			return
		}
		defer stream.Close()

		err = r.Write(stream)
		if err != nil {
			http.Error(w, "Failed to forward request", 502)
			return
		}

		// read response from tunnel
		resp, err := http.ReadResponse(bufio.NewReader(stream), r)
		if err != nil {
			http.Error(w, "Failed to read response from tunnel", 502)
			return
		}

		defer resp.Body.Close()

		// copy headers
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)

	})

	log.Println("HTTP server running on :8090 (subdomain router)")
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func startTunnelServer() {
	ln, err := net.Listen("tcp", ":7000")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Tunnel server listening on :7000")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error : ", err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	line, err := reader.ReadBytes('\n')
	if err != nil {
		log.Println("Failed to read register msg : ", err)
		return
	}

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

	if reg.Token != AUTH_TOKEN {
		log.Println("Invalid token from client")
		return
	}
	log.Println(reg)

	sub := strings.ToLower(strings.TrimSpace(reg.Subdomain))
	if sub == "" {
		log.Println("Empty subdomain not allowed")
		return
	}

	session, err := yamux.Server(&bufferedConn{Conn: conn, reader: reader},nil)
	if err != nil {
		log.Println("Yamux server error ", err)
	}

	mu.Lock()
	sessions[sub] = session
	mu.Unlock()

	log.Println("Registered subdomain", sub)

	<-session.CloseChan()

	mu.Lock()
	delete(sessions, sub)
	mu.Unlock()

	log.Println("client disconnected for subdomain", sub)

}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}


func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}