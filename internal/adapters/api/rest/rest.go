package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	storeType "github.com/playmixer/single-auth/internal/adapters/storage/types"
	"github.com/playmixer/single-auth/pkg/logger"
	"go.uber.org/zap"
)

const (
	ContentLength   string = "Content-Length"   // заголовок длины конетента
	ContentType     string = "Content-Type"     // заколовок типа контент
	ApplicationJSON string = "application/json" // json контент

	CookieJWT          string = "singleauth_token" // поле хранения токента
	CookieRefreshToken string = "singleauth_refresh"

	ttlCacheDefault = time.Second * 30
)

var (
	errInvalidAuthCookie = errors.New("invalid authorization cookie")

	shutdownDelay = time.Second * 5
)

type AuthManager interface {
	VerifyJWT(signedData string) (map[string]string, bool)
	CreateJWT(map[string]string) (string, error)

	GetUser(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)
	UpdUser(ctx context.Context, user *models.User) error

	GetPayloadUser(ctx context.Context, appID string, data map[string]string) (params, appLink string, err error)
	GenRefreshToken(ctx context.Context, userID uint) (string, error)
	UpdRefreshToken(ctx context.Context, refresh string) (string, error)
	Logout(ctx context.Context, refresh string) error
}

type AdminManager interface {
	CreateNewUser(ctx context.Context, login, email, passwordHash string) (*models.User, error)
	FindUsersByLogin(ctx context.Context, login string) ([]models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)
	RemoveUser(ctx context.Context, userID uint) error
	UpdUser(ctx context.Context, user *models.User) error

	CreateApplication(ctx context.Context, title, link string) (*models.Application, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error)
	UpdateApplication(ctx context.Context, app *models.Application) error
	RemoveApplication(ctx context.Context, appID string) error
}

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	GetH(ctx context.Context, key string, obj storeType.ObjInterface) (err error)
	SetH(ctx context.Context, key string, value storeType.ObjInterface, ttl time.Duration) error
}

type Server struct {
	log                *logger.Logger
	auth               AuthManager
	admin              AdminManager
	cache              Cache
	baseURL            string
	trustedSubnet      string
	secretKey          []byte
	cookieDomain       []string
	cookieSecure       bool
	cookieLifeTime     int
	jwtAccessTokenTTL  int
	jwtRefreshTokenTTL int
	s                  http.Server
	tlsEnable          bool
}

type Option func(s *Server)

// New создает Server.
func New(auth AuthManager, admin AdminManager, cache Cache, log *logger.Logger, options ...Option) *Server {
	srv := &Server{
		auth:      auth,
		admin:     admin,
		cache:     cache,
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

func SetCookieDomain(domain []string) Option {
	return func(s *Server) {
		s.cookieDomain = domain
	}
}

func SetCookieSecure(secure bool) Option {
	return func(s *Server) {
		s.cookieSecure = secure
	}
}

func SetCookieLifeTime(ttl int) Option {
	return func(s *Server) {
		s.cookieLifeTime = ttl
	}
}

func SetTTLAccessToken(ttl int) Option {
	return func(s *Server) {
		s.jwtAccessTokenTTL = ttl
	}
}

func SetTTLRefreshToken(ttl int) Option {
	return func(s *Server) {
		s.jwtRefreshTokenTTL = ttl
	}
}

func (s *Server) SetupRouter() *gin.Engine {
	r := gin.New()
	r.LoadHTMLGlob("templates/**/*")
	r.Use(
		s.middlewareLogger(),
	)

	r.GET("/auth/login", s.handlerLogin)
	r.GET("/auth/logout", s.handlerLogut)
	r.POST("/api/login", s.handlerAPILogin)

	auth := r.Group("/")
	auth.Use(s.middlewareCheckCookies())
	{
		auth.GET("/profile", s.handlerUserProfile)
		auth.POST("/profile/password", s.handlerUserProfileChangePassword)

		auth.GET("/api/user/authInfo", s.handlerAPIUserAuthInfo)
	}
	admin := r.Group("/admin")
	admin.Use(s.middlewareCheckCookies(), s.middlewareIsAdmin())
	{
		admin.GET("/", s.handlerAdmin)
		admin.GET("/users", s.handlerAdminUsers)
		admin.POST("/users", s.handlerAdminNewUser)
		admin.POST("/users/:userID/delete", s.handlerAdminRemoveUser)
		admin.POST("/users/:userID/update", s.handlerAdminUpdUser)
		admin.GET("/applications", s.handlerAdminApplications)
		admin.POST("/applications", s.handlerAdminApplicationNew)
		admin.POST("/applications/:appID/delete", s.handlerAdminRemoveApplication)
		admin.POST("/applications/:appID/update", s.handlerAdminUpdApplication)

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
