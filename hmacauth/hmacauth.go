package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const allowedSkew = 10 * time.Minute

func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

func hmacsFromEnv() []string {
	return strings.Split(os.Getenv("HMAC_KEYS"), ",")
}

func HMACAuthMiddleware() gin.HandlerFunc {
	keys := os.Getenv("HMAC_KEYS")

	if keys == "" {
		log.Fatal("Please set HMAC_KEYS environment variable")
	}

	return func(c *gin.Context) {
		macStr := c.Request.Header["Request-Hmac"][0]
		mac, err := parseHMAC(macStr)
		if err != nil {
			respondWithError(c, 401, "invalid request HMAC")
			return
		}

		hmkeys := hmacsFromEnv()
		err = validateHMAC(mac, hmkeys[0])
		if err != nil {
			respondWithError(c, 401, err.Error())
		}

		c.Next()
	}
}

type HMAC struct {
	Timestamp time.Time
	MAC       []byte
}

func validateHMAC(mac *HMAC, key string) error {
	now := time.Now()
	if mac.Timestamp.After(now.Add(allowedSkew)) || mac.Timestamp.Before(now.Add(-allowedSkew)) {
		return fmt.Errorf("HMAC timestamp %d is outside the allowed range", mac.Timestamp.Unix())
	}

	if hmac.Equal(mac.MAC, computeHMAC256(key, mac.Timestamp)) {
		return nil
	}

	return errors.New("invalid HMAC")
}

func parseHMAC(value string) (*HMAC, error) {
	tokens := strings.Split(value, ".")
	if len(tokens) != 2 {
		return nil, fmt.Errorf("HMAC %q not in correct format", value)
	}

	ts, err := strconv.ParseInt(tokens[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s invalid timestamp: %w", tokens[0], err)
	}

	hexmac := tokens[1]
	if hexmac == "" {
		return nil, fmt.Errorf("HMAC '%s' not in correct format", value)
	}

	mac, err := hex.DecodeString(hexmac)
	if err != nil {
		return nil, fmt.Errorf("%s could not be decoded as hex", hexmac)
	}

	return &HMAC{Timestamp: time.Unix(ts, 0), MAC: mac}, nil
}

func computeHMAC256(key string, ts time.Time) []byte {
	mac := hmac.New(sha256.New, []byte(key))

	buf := make([]byte, 0, mac.Size())
	buf = strconv.AppendInt(buf, ts.Unix(), 10)

	mac.Write(buf)
	expectedMAC := mac.Sum(buf[:0])

	return expectedMAC
}
