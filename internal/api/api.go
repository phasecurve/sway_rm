package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/phasecurve/sway_rm/internal"
	"github.com/phasecurve/sway_rm/internal/components"
	"github.com/phasecurve/sway_rm/internal/middleware"
	"github.com/phasecurve/sway_rm/internal/security"
	"github.com/phasecurve/sway_rm/templates"
)

const (
	apiKeyCookieName = "api-key"
	shortCodeFormID  = "short-code"
)

type ShortCodeGenerator func() string
type APICodeGenerator func() string

type Server struct {
	ShortCodeGenerator ShortCodeGenerator
	APICodeGenerator   APICodeGenerator
	KeyStore           *security.KeyStore
	currentPairingCode string
	pairingCodeExpiry  time.Time
}

func (s *Server) GetCurrentPairingCode() string {
	return s.currentPairingCode
}

func (s *Server) GetPairingCodeExpiry() time.Time {
	return s.pairingCodeExpiry
}

func NewServer(keyStore *security.KeyStore, shortCodeGenerator ShortCodeGenerator, apiCodeGenerator APICodeGenerator) *Server {
	return &Server{
		ShortCodeGenerator: shortCodeGenerator,
		APICodeGenerator:   apiCodeGenerator,
		KeyStore:           keyStore,
	}
}

func (s *Server) SetupRoutes(router *gin.Engine) {
	api := router.Group("/")

	api.Use(middleware.PairRefresh(s.KeyStore))

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
	if state != internal.StatePaired && (s.currentPairingCode == "" || s.pairingCodeExpiry.Before(time.Now())) {
		s.currentPairingCode = s.ShortCodeGenerator()
		s.pairingCodeExpiry = time.Now().Add(5 * time.Minute)
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

	if code != s.GetCurrentPairingCode() {
		c.Header("Content-Type", "text/html")
		component := components.PairFormWithError("Invalid pairing code. Please try again.")
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	apiKey := s.APICodeGenerator()

	s.KeyStore.StoreAPIKey(apiKey, time.Now().Add(1*time.Hour))
	c.SetCookie(apiKeyCookieName, apiKey, 3600, "/", "", false, true)
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, "<p>Paired</p>")
}
