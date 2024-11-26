package radiustls

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	util "github.com/ca-ciu/oidc-radius/pkg/util"
	"github.com/go-redis/redis"
	"github.com/okzk/go-ciba"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func handleTLSConnection(conn net.Conn, client *ciba.Client, redisClient *redis.Client, secret []byte) {
	defer conn.Close()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err.Error() != "EOF" {
				log.Printf("[ERROR] failed to read from TLS connection: %v", err)
			}
			break
		}

		packet, err := radius.Parse(buffer[:n], secret)
		if err != nil {
			log.Printf("[ERROR] failed to parse RADIUS packet: %v", err)
			continue
		}

		if packet.Code == radius.CodeAccessRequest {
			handleAccessRequest(conn, packet, client, redisClient)
		} else {
			log.Printf("[ERROR] unsupported RADIUS packet type: %v", packet.Code)
		}
	}
}

func handleAccessRequest(conn net.Conn, packet *radius.Packet, client *ciba.Client, redisClient *redis.Client) {
	username := rfc2865.UserName_GetString(packet)
	password := rfc2865.UserPassword_GetString(packet)

	if username == "" || password == "" {
		log.Printf("[INFO] invalid request: missing username or password")
		sendResponse(conn, packet.Response(radius.CodeAccessReject))
		return
	}

	cacheKey := util.GenCacheKey(username, password)
	if cached, _ := redisClient.Get(cacheKey).Result(); cached == username {
		log.Printf("[INFO] cache hit: authentication success for user %s", username)
		sendResponse(conn, packet.Response(radius.CodeAccessAccept))
		return
	}

	// Authenticate using CIBA
	ctx := context.Background() // コンテキストを作成
	token, err := client.Authenticate(ctx, ciba.LoginHint(username), ciba.UserCode(password))
	if err != nil {
		log.Printf("[INFO] authentication failed for user %s: %v", username, err)
		sendResponse(conn, packet.Response(radius.CodeAccessReject))
		return
	}

	sub, ok := token.Claims()["sub"].(string)
	if !ok || sub != username {
		log.Printf("[INFO] invalid sub claim: expected %s, got %s", username, sub)
		sendResponse(conn, packet.Response(radius.CodeAccessReject))
		return
	}

	log.Printf("[INFO] authentication success for user %s", username)
	redisClient.Set(cacheKey, username, 8*time.Hour)
	sendResponse(conn, packet.Response(radius.CodeAccessAccept))
}

func sendResponse(conn net.Conn, response *radius.Packet) {
	encoded, err := response.Encode()
	if err != nil {
		log.Printf("[ERROR] failed to encode response: %v", err)
		return
	}

	if _, err := conn.Write(encoded); err != nil {
		log.Printf("[ERROR] failed to send response: %v", err)
	}
}

func RadiusTLS(client *ciba.Client, redisClient *redis.Client, secret []byte) {
	// TLS Certs from ENV
	radiusTLSCert := util.GetEnv("RADIUS_TLS_CERT", "/etc/radius/cert.pem")
	radiusTLSKey := util.GetEnv("RADIUS_TLS_KEY", "/etc/radius/key.pem")

	go func() {
		cert, err := tls.LoadX509KeyPair(radiusTLSCert, radiusTLSKey)
		if err != nil {
			log.Fatalf("failed to load key pair: %v", err)
		}

		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err := tls.Listen("tcp", ":2083", tlsConfig)
		if err != nil {
			log.Fatalf("failed to start TLS listener: %v", err)
		}
		defer listener.Close()

		log.Printf("RADIUS over TLS server listening on :2083")

		// TLS接続を処理
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("[ERROR] failed to accept connection: %v", err)
				continue
			}
			go handleTLSConnection(conn, client, redisClient, secret)
		}
	}()
}
