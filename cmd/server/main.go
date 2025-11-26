package main

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	bolt "go.etcd.io/bbolt"

	"github.com/phasecurve/sway_rm/internal/api"
	"github.com/phasecurve/sway_rm/internal/security"
)

func main() {
	slogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger := slog.NewLogLogger(slogger.Handler(), slog.LevelInfo)

	db, err := bolt.Open("apikeys.db", 0600, nil)
	if err != nil {
		slogger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	keyStore := security.NewKeyStore(db)
	scg := security.GenerateShortCode
	acg := security.GenerateAPIKey

	server := api.NewServer(keyStore, scg, acg, os.Stdout, logger)

	r := gin.Default()
	server.SetupRoutes(r)
	r.Run("0.0.0.0:8080")
}
