package main

// Run with:
//
// HMAC_KEYS=deadbeef go run hmacauth.go

import (
	"github.com/gin-gonic/gin"
	"github.com/rubiojr/gin-middleware/hmacauth"
)

func Hello(c *gin.Context) {
	resp := map[string]string{"hello": "world"}
	c.JSON(200, resp)
}

func main() {
	api := gin.Default()

	authed := api.Group("/admin")
	authed.Use(hmacauth.HMACAuthMiddleware())
	authed.GET("/hello", Hello)

	api.Run(":5000")
}
