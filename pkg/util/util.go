package util

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
)

func GenCacheKey(keys ...string) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("\n@@@@@@@@@\n"))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
