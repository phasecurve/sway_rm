package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phasecurve/sway_rm/internal/security"
)

func PairRefresh(keyStore *security.KeyStore) gin.HandlerFunc {
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
		keyStore.StoreAPIKey(apiKey, newExpiry)

		ctx.Next()
	}
}
