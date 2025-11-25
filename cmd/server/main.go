package main

import (
	"log"

	"github.com/gin-gonic/gin"
	bolt "go.etcd.io/bbolt"

	"github.com/phasecurve/sway_rm/internal/api"
	"github.com/phasecurve/sway_rm/internal/security"
)

func main() {
	db, err := bolt.Open("apikeys.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	keyStore := security.NewKeyStore(db)

	server := api.NewServer(keyStore, nil, func() string {
		return "1234567890"
	})

	r := gin.Default()
	server.SetupRoutes(r)
	r.Run("0.0.0.0:8080")
}
