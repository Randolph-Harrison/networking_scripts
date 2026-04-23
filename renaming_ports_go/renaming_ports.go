package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/joho/godotenv"
)

const (
	SysDescription = "1.3.6.1.2.1.1.1.0"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// reader := bufio.NewReader(os.Stdin)
	// fmt.Print("Enter your full name: ")
	// input, _ := reader.ReadString('\n')

	// fmt.Println(input)
	g := &gosnmp.GoSNMP{
		Target:        os.Getenv("SWITCH_IP"),
		Port:          161,
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(5 * time.Second),
		MsgFlags:      gosnmp.AuthPriv,
		SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 os.Getenv("SNMP_USER"),
			AuthenticationProtocol:   gosnmp.MD5,
			AuthenticationPassphrase: os.Getenv("SNMP_PASS"),
			PrivacyProtocol:          gosnmp.AES,
			PrivacyPassphrase:        os.Getenv("SNMP_PRIV"),
		},
	}
	err = g.Connect()
	if err != nil {
		log.Fatalf("ERROR: failed to connect: %v", err)
	}
	defer g.Conn.Close()

	oids := []string{SysDescription}
	result, err := g.Get(oids)
	if err != nil {
		log.Fatalf("ERROR: failed getting SNMP: %v", err)
	}

	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		bytes := variable.Value.([]byte)
		fmt.Printf("string: %s\n", string(bytes))
	}
}
