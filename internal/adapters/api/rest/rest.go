package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
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

	CookieNameToken string = "singleauth_token" // поле хранения токента

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
	log           *logger.Logger
	auth          AuthManager
	admin         AdminManager
	cache         Cache
	baseURL       string
	trustedSubnet string
	secretKey     []byte
	cookieDomain  []string
	cookieSecure  bool
	s             http.Server
	tlsEnable     bool
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

func (s *Server) baseLink(short string) string {
	return fmt.Sprintf("%s/%s", s.baseURL, short)
}

func (s *Server) checkAuth(c *gin.Context) (userID string, err error) {
	var ok bool
	var tknData map[string]string
	cookieUserID, err := c.Request.Cookie(CookieNameToken)
	if err == nil {
		tknData, ok = s.auth.VerifyJWT(cookieUserID.Value)
		s.log.Debug("cookie", zap.String("value", cookieUserID.Value), zap.Any("params", tknData))
	}
	if err != nil {
		return "", fmt.Errorf("failed reade user cookie: %w %w", errInvalidAuthCookie, err)
	}
	if !ok {
		return "", fmt.Errorf("unverify usercookie: %w", errInvalidAuthCookie)
	}
	if userID, ok = tknData["userID"]; ok {
		return userID, nil
	}

	return "", fmt.Errorf("failed to read user id from token: %w", errInvalidAuthCookie)
}

func (s *Server) isAuthenticate(c *gin.Context) (isAuth bool, user *models.User, err error) {
	userID, err := s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		key := "userid:" + userID
		if err = s.cache.GetH(c.Request.Context(), key, user); err != nil {
			user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
			if err != nil {
				isAuth = false
				return
			}

			err = s.cache.SetH(c.Request.Context(), key, user, time.Minute)
			if err != nil {
				s.log.Error("failed save user to cache", zap.Error(err))
			}
		}
	}
	if err == nil {
		isAuth = true
	}
	return
}

func empty[T string | int](s T) bool {
	val := reflect.ValueOf(s)

	switch val.Kind() {
	case reflect.String:
		return val.String() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int() == 0
	default:
		// Для других типов данных можно добавить дополнительную логику
		return false
	}
}
