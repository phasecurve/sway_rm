package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/phasecurve/sway_rm/internal"
	"github.com/phasecurve/sway_rm/internal/components"
	"github.com/phasecurve/sway_rm/internal/security"
	"github.com/phasecurve/sway_rm/templates"
)

const (
	API_KEY_COOKIE_NAME = "api-key"
	SHORT_CODE_FORM_ID  = "short-code"
)

type ShortCodeGenerator func() string
type APICodeGenerator func() string

type Server struct {
	ShortCodeGenerator ShortCodeGenerator
	APICodeGenerator   APICodeGenerator
	KeyStore           *security.KeyStore
}

func NewServer(keyStore *security.KeyStore, shortCodeGenerator ShortCodeGenerator, apiCodeGenerator APICodeGenerator) *Server {
	server := &Server{
		ShortCodeGenerator: shortCodeGenerator,
		APICodeGenerator:   apiCodeGenerator,
		KeyStore:           keyStore,
	}
	return server
}

func (s *Server) SetupRoutes(router *gin.Engine) {
	router.GET("/", s.getRoot)
	router.GET("/api/status", s.getStatus)
	router.POST("/api/pair", s.postPair)
}

func (s *Server) getRoot(c *gin.Context) {
	state := internal.StateUnpaired
	for _, cookie := range c.Request.Cookies() {
		if cookie.Name == API_KEY_COOKIE_NAME {
			valid := s.KeyStore.ValidateAPIKey(cookie.Value)
			if valid {
				state = internal.StatePaired
			} else {
				state = internal.StateExpired
			}
			break
		}
	}
	component := templates.Launch(state)
	component.Render(c.Request.Context(), c.Writer)
}

func (s *Server) getStatus(c *gin.Context) {
	c.Status(http.StatusUnauthorized)
}

func (s *Server) postPair(c *gin.Context) {
	code := c.PostForm(SHORT_CODE_FORM_ID)

	fmt.Printf("Found %s in the form post.\n", code)

	if code != "123456" {
		c.Header("Content-Type", "text/html")
		component := components.PairFormWithError("Invalid pairing code. Please try again.")
		component.Render(c.Request.Context(), c.Writer)
		return
	}

	apiKey := s.APICodeGenerator()

	fmt.Printf("Putting %s in the response.\n", apiKey)

	c.SetCookie(API_KEY_COOKIE_NAME, apiKey, 3600, "/", "", false, true)
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, "<p>Paired</p>")
}
