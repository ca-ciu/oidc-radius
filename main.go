package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	radiustls "github.com/ca-ciu/oidc-radius/pkg/radiustls"
	util "github.com/ca-ciu/oidc-radius/pkg/util"
	"github.com/go-redis/redis"
	"github.com/okzk/go-ciba"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func main() {
	client := ciba.NewClient(
		os.Getenv("CIBA_ISSUER"),
		os.Getenv("CIBA_AUTHN_ENDPOINT"),
		os.Getenv("CIBA_TOKEN_ENDPOINT"),
		os.Getenv("CIBA_SCOPE"),
		os.Getenv("CIBA_CLIENT_ID"),
		os.Getenv("CIBA_CLIENT_SECRET"),
	)
	sep := os.Getenv("USERNAME_SEPARATOR")
	acceptCaseInsensitiveUsername := os.Getenv("ACCEPT_CASE_INSENSITIVE_USERNAME") == "1"

	expiration := 8 * time.Hour
	expirationStr := os.Getenv("CACHE_EXPIRATION_SEC")
	if expirationStr != "" {
		s, err := strconv.Atoi(expirationStr)
		if err != nil || s <= 0 {
			panic("invalid CACHE_EXPIRATION_SEC env")
		}
		expiration = time.Duration(s) * time.Second
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:        fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
		Password:    os.Getenv("REDIS_PASSWORD"),
		DialTimeout: time.Millisecond * 300,
		ReadTimeout: time.Millisecond * 300,
	})

	accessRequestHandler := func(w radius.ResponseWriter, r *radius.Request) {
		if r.Code != radius.CodeAccessRequest {
			return
		}
		username := rfc2865.UserName_GetString(r.Packet)
		password := ""
		if sep != "" {
			parts := strings.SplitN(username, sep, 2)
			if len(parts) == 2 {
				username = parts[0]
				password = parts[1]
			}
		}
		if password == "" {
			password = rfc2865.UserPassword_GetString(r.Packet)
		}
		if username == "" || password == "" {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		cacheKey := util.GenCacheKey(username, password)
		ret, _ := redisClient.Get(cacheKey).Result()
		if ret == username {
			log.Printf("[INFO] (cache) authn success. user: %s", username)
			w.Write(r.Response(radius.CodeAccessAccept))
			return
		}

		token, err := client.Authenticate(r.Context(), ciba.LoginHint(username), ciba.UserCode(password))
		if err != nil {
			log.Printf("[INFO] authn failed. user: %s, error: %v", username, err)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		sub, ok := token.Claims()["sub"].(string)
		if !ok {
			log.Printf("[INFO] authn failed. user: %s, error: missing_sub", username)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		if acceptCaseInsensitiveUsername && !strings.EqualFold(sub, username) {
			log.Printf("[INFO] authn failed. user: %s, returned_sub: %s", username, sub)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		if !acceptCaseInsensitiveUsername && sub != username {
			log.Printf("[INFO] authn failed. user: %s, returned_sub: %s", username, sub)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		log.Printf("[INFO] authn success. user: %s", username)
		redisClient.Set(cacheKey, username, expiration)
		w.Write(r.Response(radius.CodeAccessAccept))
	}

	accountingRequestHandler := func(w radius.ResponseWriter, r *radius.Request) {
		if r.Code != radius.CodeAccountingRequest {
			return
		}
		w.Write(r.Response(radius.CodeAccountingResponse))
	}

	secret := []byte(os.Getenv("RADIUS_SECRET"))
	radisAccountPort := util.GetEnv("RADIUS_ACCOUNT_PORT", "1813")

	// Radius Accounting
	go func() {
		server := radius.PacketServer{
			Addr:         ":" + radisAccountPort,
			Handler:      radius.HandlerFunc(accountingRequestHandler),
			SecretSource: radius.StaticSecretSource(secret),
		}
		log.Printf("RADIUS accountingRequestHandler start listening on :" + radisAccountPort)
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	// Radius TLS
	go radiustls.RadiusTLS(client, redisClient, secret)

	// Radius Request
	radisRequestPort := util.GetEnv("RADIUS_REQUEST_PORT", "1812")
	server := radius.PacketServer{
		Addr:         ":" + radisRequestPort,
		Handler:      radius.HandlerFunc(accessRequestHandler),
		SecretSource: radius.StaticSecretSource(secret),
	}
	log.Printf("RADIUS accessRequestHandler start listening on :" + radisRequestPort)
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
