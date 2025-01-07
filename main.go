package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Content   string `json:"content"`
	Encrypted bool   `json:"encrypted"`
}

type Client struct {
	Conn     net.Conn
	Nickname string
	PubKey   ed25519.PublicKey
	PrivKey  ed25519.PrivateKey
}

var (
	clients = make(map[string]*Client)
	mu      sync.Mutex
)

func encodeMessage(msg Message) []byte {
	data, _ := json.Marshal(msg)
	return append(data, '\n')
}

func decodeMessage(data []byte) (Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	return msg, err
}

func broadcastMessage(sender *Client, content string) {
	mu.Lock()
	defer mu.Unlock()
	for nickname, client := range clients {
		if nickname != sender.Nickname {
			msg := Message{
				From:    sender.Nickname,
				To:      "",
				Content: content,
			}
			client.Conn.Write(encodeMessage(msg))
		}
	}
}

func sendEncryptedMessage(sender *Client, recipient *Client, content string) {
	if recipient == nil {
		return
	}

	signature := ed25519.Sign(sender.PrivKey, []byte(content))

	encodedPubKey := base64.StdEncoding.EncodeToString(sender.PubKey)

	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	msg := Message{
		From:      sender.Nickname,
		To:        recipient.Nickname,
		Content:   encodedPubKey + "|" + encodedSignature + "|" + content,
		Encrypted: true,
	}

	recipient.Conn.Write(encodeMessage(msg))
}

func handleEncryptedMessage(msg Message) {
	parts := strings.SplitN(msg.Content, "|", 3)
	if len(parts) < 3 {
		fmt.Println("Message format is incorrect")
		return
	}

	senderPublicKey, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Println("Error decoding public key:", err)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return
	}

	originalContent := parts[2]

	isValid := ed25519.Verify(senderPublicKey, []byte(originalContent), signature)
	if !isValid {
		fmt.Println("Invalid signature from sender:", msg.From)
		return
	}

	fmt.Printf("[Decrypted] %s: %s\n", msg.From, originalContent)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	nickname, _ := reader.ReadString('\n')
	nickname = strings.TrimSpace(nickname)

	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	client := &Client{
		Conn:     conn,
		Nickname: nickname,
		PubKey:   pubKey,
		PrivKey:  privKey,
	}

	mu.Lock()
	clients[nickname] = client
	mu.Unlock()

	fmt.Printf("%s has joined the chat.\n", nickname)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "@") {
			split := strings.SplitN(line, " ", 2)
			if len(split) < 2 {
				continue
			}
			targetNickname := strings.TrimPrefix(split[0], "@")
			content := split[1]

			mu.Lock()
			target, exists := clients[targetNickname]
			mu.Unlock()

			if exists {
				sendEncryptedMessage(client, target, content)
			} else {
				fmt.Fprintf(conn, "User %s not found.\n", targetNickname)
			}
		} else {
			broadcastMessage(client, line)
		}
	}

	mu.Lock()
	delete(clients, nickname)
	mu.Unlock()
	fmt.Printf("%s has left the chat.\n", nickname)
}

// Start server
func startServer(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer ln.Close()

	fmt.Println("Server started, listening on port:", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Connection error:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func startClient(serverAddr string, nickname string) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\n", nickname)
	fmt.Println("Successfully connected to the server.")

	go func() {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			msg, err := decodeMessage([]byte(line))
			if err != nil {
				fmt.Println("Error decoding message:", err)
				continue
			}

			if msg.Encrypted {
				handleEncryptedMessage(msg)
			} else {
				fmt.Printf("%s: %s\n", msg.From, msg.Content)
			}
		}
	}()

	consoleReader := bufio.NewReader(os.Stdin)
	for {
		line, _ := consoleReader.ReadString('\n')
		fmt.Fprintf(conn, "%s\n", strings.TrimSpace(line))
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  Server: go run main.go server <port>")
		fmt.Println("  Client: go run main.go client <server IP:port> <nickname>")
		return
	}

	mode := os.Args[1]
	if mode == "server" {
		port := os.Args[2]
		startServer(port)
	} else if mode == "client" {
		serverAddr := os.Args[2]
		nickname := os.Args[3]
		startClient(serverAddr, nickname)
	} else {
		fmt.Println("Unknown mode:", mode)
	}
}
