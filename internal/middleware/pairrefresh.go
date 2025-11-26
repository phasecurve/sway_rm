package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phasecurve/sway_rm/internal/security"
)

type Logger interface {
	Printf(format string, v ...interface{})
}

func PairRefresh(keyStore security.KeyStorer, logger Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		apiKey, err := ctx.Cookie("api-key")
		if err != nil {
			ctx.Next()
			return
		}

		existingKey, err := keyStore.GetAPIKey(apiKey)
		if err != nil {
			ctx.Next()
			return
		}

		if existingKey.TTL.Before(time.Now()) {
			ctx.Next()
			return
		}

		newExpiry := existingKey.TTL.Add(30 * time.Minute)
		if err := keyStore.StoreAPIKey(apiKey, newExpiry); err != nil {
			logger.Printf("failed to refresh API key TTL: %v", err)
		}

		ctx.Next()
	}
}
