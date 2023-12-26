package Bavar

import (
	"flag"
	"log"
	"os"
)

var address string
var username string
var password string

func init() {
	flag.StringVar(&address, "a", ":1080", "listen on the address")
	flag.StringVar(&username, "u", "", "username")
	flag.StringVar(&password, "p", "", "password")
	flag.Parse()
}

func main() {
	logger := log.New(os.Stderr, "[Bavar] ", log.LstdFlags)
	svc := &socks5.Server{
		Logger: logger,
	}
	if username != "" {
		svc.Authentication = socks5.UserAuth(username, password)
	}
	err := svc.ListenAndServe("tcp", address)
	if err != nil {
		logger.Println(err)
	}
}
