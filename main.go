package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"reflect"
)

type Properties struct {
	Kind  string
	Items []struct {
		Property
	}
}

type Property struct {
	CN        string
	Serial    *big.Int
	NotBefore string
	NotAfter  string
	SAN_DNS   []string
	SAN_IP    []net.IP
	Issuer    pkix.Name
}

func rcertfile(certFile *string) []*x509.Certificate {
	var cert *x509.Certificate
	var certs []*x509.Certificate
	certPEM, err := ioutil.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("failed to load certificate: " + err.Error())
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Fatalf("failed to parse certificate PEM")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: " + err.Error())
	}
	certs = []*x509.Certificate{cert}

	return certs
}

func rcerturl(certUrl *string) []*x509.Certificate {
	var certs []*x509.Certificate
	log.Printf("Connecting to %s\n", *certUrl)
	config := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", *certUrl, &config)
	if err != nil {
		log.Fatalf("Failed to connect: " + err.Error())
	}
	defer conn.Close()
	log.Printf("Connection established between %s and localhost.\n", conn.RemoteAddr().String())
	state := conn.ConnectionState()
	certs = state.PeerCertificates
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	log.Print("client: exiting")
	return certs
}

func parsecert(certs []*x509.Certificate) {
	//var property Property
	for _, v := range certs {
		//property := []Property{}
		cert, err := x509.ParseCertificate(v.Raw)
		if err != nil {
			log.Fatalf("failed to parse certificate: " + err.Error())
		}
		p := Property{
			CN:        cert.Subject.CommonName,
			Serial:    cert.SerialNumber,
			NotBefore: cert.NotBefore.String(),
			NotAfter:  cert.NotAfter.String(),
			SAN_DNS:   cert.DNSNames,
			SAN_IP:    cert.IPAddresses,
			Issuer:    cert.Issuer,
		}
		//property = append(property, p)
		//fmt.Printf("%s", property)
		fmt.Print("=======================\n")
		presults(p)
		fmt.Print("=======================\n")
	}
	//return property
}

func presults(property Property) {
	s := reflect.ValueOf(&property).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		fmt.Printf("%d: %s: %+v\n",
			i, typeOfT.Field(i).Name, f.Interface())
	}
}

func main() {
	certFile := flag.String("certfile", "", "certfile to load")
	certUrl := flag.String("certurl", "", "certurl to load")
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *certFile != "" {
		parsecert(rcertfile(certFile))
	} else if *certUrl != "" {
		parsecert(rcerturl(certUrl))
	}
}
