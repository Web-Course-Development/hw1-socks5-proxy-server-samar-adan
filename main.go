package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "Port to listen on")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	log.Printf("SOCKS5 proxy listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := negotiateAuth(conn); err != nil {
		log.Printf("Auth negotiation failed: %v", err)
		return
	}

	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("CONNECT failed: %v", err)
		return
	}
	defer target.Close()

	relay(conn, target)
}

// negotiateAuth handles the SOCKS5 greeting and optional username/password auth.
func negotiateAuth(conn net.Conn) error {
	// Read VER + NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading greeting header: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading methods: %w", err)
	}

	proxyUser := os.Getenv("PROXY_USER")
	requireAuth := proxyUser != ""

	if requireAuth {
		// Look for method 0x02
		found := false
		for _, m := range methods {
			if m == 0x02 {
				found = true
				break
			}
		}
		if !found {
			conn.Write([]byte{0x05, 0xFF})
			return fmt.Errorf("client does not support username/password auth")
		}
		conn.Write([]byte{0x05, 0x02})
		return authenticateUserPass(conn)
	}

	// No auth required — look for method 0x00
	for _, m := range methods {
		if m == 0x00 {
			conn.Write([]byte{0x05, 0x00})
			return nil
		}
	}
	conn.Write([]byte{0x05, 0xFF})
	return fmt.Errorf("no acceptable auth method")
}

// authenticateUserPass performs RFC 1929 sub-negotiation.
func authenticateUserPass(conn net.Conn) error {
	// VER (must be 0x01)
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return fmt.Errorf("reading auth ver: %w", err)
	}
	if ver[0] != 0x01 {
		return fmt.Errorf("bad auth sub-negotiation version: %d", ver[0])
	}

	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return err
	}
	uname := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(uname) == expectedUser && string(passwd) == expectedPass {
		conn.Write([]byte{0x01, 0x00}) // success
		return nil
	}
	conn.Write([]byte{0x01, 0x01}) // failure
	return fmt.Errorf("invalid credentials")
}

// handleConnect reads the CONNECT request, dials the target, and sends the reply.
func handleConnect(conn net.Conn) (net.Conn, error) {
	// VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading request header: %w", err)
	}
	if header[0] != 0x05 {
		return nil, fmt.Errorf("bad version in request: %d", header[0])
	}
	if header[1] != 0x01 {
		sendReply(conn, 0x07) // command not supported
		return nil, fmt.Errorf("unsupported command: %d", header[1])
	}

	atyp := header[3]
	var host string

	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	default:
		sendReply(conn, 0x08) // address type not supported
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := fmt.Sprintf("%s:%d", host, port)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		sendReply(conn, 0x04) // host unreachable
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	sendReply(conn, 0x00) // success
	return targetConn, nil
}

// sendReply sends a SOCKS5 reply with the given REP code.
func sendReply(conn net.Conn, rep byte) {
	reply := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(reply)
}

// relay bidirectionally copies data between client and target.
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}
