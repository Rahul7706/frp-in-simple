package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	VPS_ADDR = "127.0.0.1:7000"
	LOCAL_ADDR = "127.0.0.1:3000"
	SUBDOMAIN ="a"
	TOKEN = "secret123"
)

type RegisterMsg struct {
	Type  string  `json:"type"`
	Subdomain string `json:"subdomain"`
	Token  string `json:"token"`
}

func main(){
	for{
		err := startClient()
		log.Println("Disconnected. Reconnecting in 3 seconds ... ",err)
		time.Sleep(3*time.Second)
	}
}


func startClient()error{
	conn,err := net.Dial("tcp",VPS_ADDR)
	if err != nil {
		return  err
	}
	defer  conn.Close()
	reg :=RegisterMsg{
		Type: "register",
		Subdomain: SUBDOMAIN,
		Token: TOKEN,
	}

	b,_:=json.Marshal(reg)
	b=append(b, '\n')
	_, err = conn.Write(b)
	if err!=nil{
		return   err
	}


	log.Println("Registered subdomain:", SUBDOMAIN)

	session, err := yamux.Client(conn, nil)

	for {
		stream,err:=session.Accept()
		if err!=nil{
			return err
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	localConn,err :=net.Dial("tcp",LOCAL_ADDR)
	if err !=nil{
		log.Println("Local service connection failed:",err)
		return
	}
	defer localConn.Close()
	go io.Copy(localConn,stream)

	io.Copy(stream,localConn)
}