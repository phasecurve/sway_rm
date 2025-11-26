package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/phasecurve/sway_rm/internal"
	"github.com/phasecurve/sway_rm/internal/components"
	"github.com/phasecurve/sway_rm/internal/middleware"
	"github.com/phasecurve/sway_rm/templates"
)

const (
	apiKeyCookieName = "api-key"
	shortCodeFormID  = "short-code"
)

type ShortCodeGenerator func() string
type APICodeGenerator func() string

func (s *Server) SetupRoutes(router *gin.Engine) {
	api := router.Group("/")

	api.Use(middleware.PairRefresh(s.KeyStore, s.Logger))

	api.GET("/", s.getRoot)
	api.GET("/api/status", s.getStatus)
	api.POST("/api/pair", s.postPair)
}

func (s *Server) getRoot(c *gin.Context) {
	state := internal.StateUnpaired
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == apiKeyCookieName {
			valid := s.KeyStore.ValidateAPIKey(cookie.Value)
			if valid {
				state = internal.StatePaired
			} else {
				state = internal.StateExpired
			}
			break
		}
	}
	if state != internal.StatePaired && (!s.isShortCodeSet() || s.hasShortCodeExpired()) {
		s.setNewShortCode()
		s.setNewShortCodeExpiry()
		s.publishShortCode()
	}
	component := templates.Launch(state)
	component.Render(c.Request.Context(), c.Writer)
}

func (s *Server) getStatus(c *gin.Context) {
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == apiKeyCookieName {
			if s.KeyStore.ValidateAPIKey(cookie.Value) {
				c.Status(http.StatusOK)
				return
			}
			break
		}
	}
	c.Status(http.StatusUnauthorized)
}

func (s *Server) postPair(c *gin.Context) {
	code := c.PostForm(shortCodeFormID)

	if code != s.getCurrentPairingCode() {
		c.Header("Content-Type", "text/html")
		component := components.PairFormWithError("Invalid pairing code. Please try again.")
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	apiKey := s.APICodeGenerator()

	if err := s.KeyStore.StoreAPIKey(apiKey, time.Now().Add(1*time.Hour)); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.SetCookie(apiKeyCookieName, apiKey, 3600, "/", "", false, true)
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, "<p>Paired</p>")
	s.resetPairingCode()
}
