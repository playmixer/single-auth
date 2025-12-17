package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/types"
	"github.com/playmixer/single-auth/pkg/logger"
	"go.uber.org/zap"
)

const (
	ContentLength   string = "Content-Length"   // заголовок длины конетента
	ContentType     string = "Content-Type"     // заколовок типа контент
	ApplicationJSON string = "application/json" // json контент

	CookieNameToken string = "token" // поле хранения токента
)

var (
	errInvalidAuthCookie = errors.New("invalid authorization cookie")

	shutdownDelay = time.Second * 5
)

type AuthManager interface {
	VerifyJWT(signedData string) (map[string]string, bool)
	CreateJWT(map[string]string) (string, error)

	GetUser(ctx context.Context, username string) (*types.User, error)
	GetUserByID(ctx context.Context, userID uint) (*types.User, error)

	GetPayloadUser(appID string, data map[string]string) (params, appLink string, err error)
}

type Server struct {
	log           *logger.Logger
	auth          AuthManager
	baseURL       string
	trustedSubnet string
	secretKey     []byte
	s             http.Server
	tlsEnable     bool
}

type Option func(s *Server)

// New создает Server.
func New(auth AuthManager, log *logger.Logger, options ...Option) *Server {
	srv := &Server{
		auth:      auth,
		log:       log,
		secretKey: []byte("rest_secret_key"),
	}
	srv.s.Addr = "localhost:8080"

	for _, opt := range options {
		opt(srv)
	}

	return srv
}
func BaseURL(url string) func(*Server) {
	return func(s *Server) {
		s.baseURL = url
	}
}

// Addr - Насткройка сервера, задает адрес сервера.
func Addr(addr string) func(s *Server) {
	return func(s *Server) {
		s.s.Addr = addr
	}
}

// SecretKey - задает секретный ключ.
func SecretKey(secret []byte) Option {
	return func(s *Server) {
		s.secretKey = secret
	}
}

// HTTPSEnable - включает https.
func HTTPSEnable(enable bool) Option {
	return func(s *Server) {
		s.tlsEnable = enable
	}
}

func (s *Server) SetupRouter() *gin.Engine {
	r := gin.New()
	r.LoadHTMLGlob("templates/*")
	r.Use(
		s.middlewareLogger(),
	)

	r.GET("/auth/login", s.handlerLogin)
	r.GET("/auth/logout", s.handlerLogut)
	r.POST("/api/login", s.handlerAPILogin)
	auth := r.Group("/")
	{
		auth.Use(s.middlewareCheckCookies())
		auth.GET("/api/user/authInfo", s.handlerAPIUserAuthInfo)

	}

	return r
}

func (s *Server) Run() error {
	s.s.Handler = s.SetupRouter().Handler()
	if err := s.s.ListenAndServe(); err != nil {
		return fmt.Errorf("server has failed: %w", err)
	}

	return nil
}

// Stop - остановка сервера.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownDelay)
	defer cancel()
	err := s.s.Shutdown(ctx)
	if err != nil {
		s.log.Error("failed shutdown server", zap.Error(err))
	}
	s.log.Info("Server exiting")
}

func (s *Server) baseLink(short string) string {
	return fmt.Sprintf("%s/%s", s.baseURL, short)
}

func (s *Server) checkAuth(c *gin.Context) (userID string, err error) {
	var ok bool
	var tknData map[string]string
	cookieUserID, err := c.Request.Cookie(CookieNameToken)
	if err == nil {
		tknData, ok = s.auth.VerifyJWT(cookieUserID.Value)
	}
	if err != nil {
		return "", fmt.Errorf("failed reade user cookie: %w %w", errInvalidAuthCookie, err)
	}
	if !ok {
		return "", fmt.Errorf("unverify usercookie: %w", errInvalidAuthCookie)
	}
	fmt.Println(cookieUserID.Value)
	if userID, ok = tknData["userID"]; ok {
		return userID, nil
	}

	return "", fmt.Errorf("failed to read user id from token: %w", errInvalidAuthCookie)
}
