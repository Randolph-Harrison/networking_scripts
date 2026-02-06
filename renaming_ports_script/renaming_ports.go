package main

import (
	"fmt"
	"log"

	g "github.com/gosnmp/gosnmp"
)

func main() {
	fmt.Println("Hello world")

	g.Default.Target = "192.168.1.10"
	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()
}
