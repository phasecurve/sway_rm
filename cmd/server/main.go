package main

import (
	"github.com/gin-gonic/gin"
	"github.com/phasecurve/sway_rm/internal/api"
	"github.com/phasecurve/sway_rm/internal/security"
)

func main() {
	keyStore := &security.KeyStore{}
	server := api.NewServer(keyStore, nil, func() string {
		return "1234567890"
	})

	r := gin.Default()
	server.SetupRoutes(r)
	r.Run("0.0.0.0:8080")
}
