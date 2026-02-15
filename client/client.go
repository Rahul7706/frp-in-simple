package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

type Config struct {
	Details struct {
		Server     string `json:"SERVER"`
		ServerPort string `json:"SERVER_PORT"`
		UserName   string `json:"USER_NAME"`
		Token      string `json:"TOKEN"`
		LocalPort  string `json:"LOCAL_PORT"`
	} `json:"details"`
}

func LoadConfig() (*Config, error) {
	file, err := os.ReadFile("config.json")
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

type RegisterMsg struct {
	Type      string `json:"type"`
	Subdomain string `json:"subdomain"`
	Token     string `json:"token"`
}

func main() {

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatal("Config load error:", err)
	}

	vpsAddr := cfg.Details.Server + ":" + cfg.Details.ServerPort
	
	localAddr := "127.0.0.1:" + cfg.Details.LocalPort

	subdomain := cfg.Details.UserName
	token := cfg.Details.Token

	for {
		err := startClient(vpsAddr, localAddr, subdomain, token)
		log.Println("Disconnected. Reconnecting in 3 seconds...", err)
		time.Sleep(3 * time.Second)
	}
}

func startClient(vpsAddr string, localAddr string, subdomain string, token string) error {

	conn, err := net.Dial("tcp", vpsAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	reg := RegisterMsg{
		Type:      "register",
		Subdomain: subdomain,
		Token:     token,
	}

	b, _ := json.Marshal(reg)
	b = append(b, '\n')

	_, err = conn.Write(b)
	if err != nil {
		return err
	}

	log.Println("Registered subdomain:", subdomain)

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	for {
		stream, err := session.Accept()
		if err != nil {
			return err
		}

		go handleStream(stream, localAddr)
	}
}

func handleStream(stream net.Conn, localAddr string) {
	defer stream.Close()

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Println("Local service connection failed:", err)
		return
	}
	defer localConn.Close()

	go io.Copy(localConn, stream)
	io.Copy(stream, localConn)
}
