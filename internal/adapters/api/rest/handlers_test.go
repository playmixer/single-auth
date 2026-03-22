package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/internal/adapters/storage/types"
	"github.com/playmixer/single-auth/pkg/authtools"
	"github.com/playmixer/single-auth/pkg/logger"
	"gorm.io/gorm"
)

// MockAuthManager implements AuthManager for testing.
type MockAuthManager struct {
	VerifyJWTFunc       func(signedData string) (map[string]string, bool)
	CreateJWTFunc       func(map[string]string) (string, error)
	GetUserFunc         func(ctx context.Context, username string) (*models.User, error)
	GetUserByIDFunc     func(ctx context.Context, userID uint) (*models.User, error)
	UpdUserFunc         func(ctx context.Context, user *models.User) error
	GetPayloadUserFunc  func(ctx context.Context, appID string, data map[string]string) (params, appLink string, err error)
	GenRefreshTokenFunc func(ctx context.Context, userID uint) (string, error)
	UpdRefreshTokenFunc func(ctx context.Context, refresh string) (string, error)
	LogoutFunc          func(ctx context.Context, refresh string) error
}

func (m *MockAuthManager) VerifyJWT(signedData string) (map[string]string, bool) {
	if m.VerifyJWTFunc != nil {
		return m.VerifyJWTFunc(signedData)
	}
	return nil, false
}

func (m *MockAuthManager) CreateJWT(data map[string]string) (string, error) {
	if m.CreateJWTFunc != nil {
		return m.CreateJWTFunc(data)
	}
	return "", errors.New("not implemented")
}

func (m *MockAuthManager) GetUser(ctx context.Context, username string) (*models.User, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(ctx, username)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAuthManager) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	if m.GetUserByIDFunc != nil {
		return m.GetUserByIDFunc(ctx, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAuthManager) UpdUser(ctx context.Context, user *models.User) error {
	if m.UpdUserFunc != nil {
		return m.UpdUserFunc(ctx, user)
	}
	return errors.New("not implemented")
}

func (m *MockAuthManager) GetPayloadUser(ctx context.Context, appID string, data map[string]string) (params, appLink string, err error) {
	if m.GetPayloadUserFunc != nil {
		return m.GetPayloadUserFunc(ctx, appID, data)
	}
	return "", "", errors.New("not implemented")
}

func (m *MockAuthManager) GenRefreshToken(ctx context.Context, userID uint) (string, error) {
	if m.GenRefreshTokenFunc != nil {
		return m.GenRefreshTokenFunc(ctx, userID)
	}
	return "", errors.New("not implemented")
}

func (m *MockAuthManager) UpdRefreshToken(ctx context.Context, refresh string) (string, error) {
	if m.UpdRefreshTokenFunc != nil {
		return m.UpdRefreshTokenFunc(ctx, refresh)
	}
	return "", errors.New("not implemented")
}

func (m *MockAuthManager) Logout(ctx context.Context, refresh string) error {
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, refresh)
	}
	return errors.New("not implemented")
}

// MockAdminManager implements AdminManager for testing.
type MockAdminManager struct {
	CreateNewUserFunc                 func(ctx context.Context, login, email, passwordHash string, admin bool) (*models.User, error)
	FindUsersByLoginFunc              func(ctx context.Context, login string) ([]models.User, error)
	GetUserByIDFunc                   func(ctx context.Context, userID uint) (*models.User, error)
	RemoveUserFunc                    func(ctx context.Context, userID uint) error
	UpdUserFunc                       func(ctx context.Context, user *models.User) error
	UpdRolesUserFunc                  func(ctx context.Context, userID uint, roles []uint) error
	CreateApplicationFunc             func(ctx context.Context, title, link string) (*models.Application, error)
	GetApplicationFunc                func(ctx context.Context, appID string) (*models.Application, error)
	FindApplicationByTitleFunc        func(ctx context.Context, title string) ([]models.Application, error)
	UpdateApplicationFunc             func(ctx context.Context, app *models.Application) error
	RemoveApplicationFunc             func(ctx context.Context, appID string) error
	CreateRoleApplicationFunc         func(ctx context.Context, appID string, name string, description string) (*models.Role, error)
	GetRoleFunc                       func(ctx context.Context, roleID uint) (*models.Role, error)
	UpdateRoleFunc                    func(ctx context.Context, roleID uint, name, description string) error
	RemoveRoleFunc                    func(ctx context.Context, roleID uint) error
	CountUsersFunc                    func(ctx context.Context) (int64, error)
	CountApplicationsFunc             func(ctx context.Context) (int64, error)
	CountActiveSessionsFunc           func(ctx context.Context) (int64, error)
	CountRolesFunc                    func(ctx context.Context) (int64, error)
	CountUsersCreatedAfterFunc        func(ctx context.Context, after time.Time) (int64, error)
	CountApplicationsCreatedAfterFunc func(ctx context.Context, after time.Time) (int64, error)
	CountRolesCreatedAfterFunc        func(ctx context.Context, after time.Time) (int64, error)
	CountSessionsCreatedAfterFunc     func(ctx context.Context, after time.Time) (int64, error)
}

func (m *MockAdminManager) CreateNewUser(ctx context.Context, login, email, passwordHash string, admin bool) (*models.User, error) {
	if m.CreateNewUserFunc != nil {
		return m.CreateNewUserFunc(ctx, login, email, passwordHash, admin)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) FindUsersByLogin(ctx context.Context, login string) ([]models.User, error) {
	if m.FindUsersByLoginFunc != nil {
		return m.FindUsersByLoginFunc(ctx, login)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	if m.GetUserByIDFunc != nil {
		return m.GetUserByIDFunc(ctx, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) RemoveUser(ctx context.Context, userID uint) error {
	if m.RemoveUserFunc != nil {
		return m.RemoveUserFunc(ctx, userID)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) UpdUser(ctx context.Context, user *models.User) error {
	if m.UpdUserFunc != nil {
		return m.UpdUserFunc(ctx, user)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) UpdRolesUser(ctx context.Context, userID uint, roles []uint) error {
	if m.UpdRolesUserFunc != nil {
		return m.UpdRolesUserFunc(ctx, userID, roles)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) CreateApplication(ctx context.Context, title, link string) (*models.Application, error) {
	if m.CreateApplicationFunc != nil {
		return m.CreateApplicationFunc(ctx, title, link)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	if m.GetApplicationFunc != nil {
		return m.GetApplicationFunc(ctx, appID)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error) {
	if m.FindApplicationByTitleFunc != nil {
		return m.FindApplicationByTitleFunc(ctx, title)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) UpdateApplication(ctx context.Context, app *models.Application) error {
	if m.UpdateApplicationFunc != nil {
		return m.UpdateApplicationFunc(ctx, app)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) RemoveApplication(ctx context.Context, appID string) error {
	if m.RemoveApplicationFunc != nil {
		return m.RemoveApplicationFunc(ctx, appID)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) CreateRoleApplication(ctx context.Context, appID string, name string, description string) (*models.Role, error) {
	if m.CreateRoleApplicationFunc != nil {
		return m.CreateRoleApplicationFunc(ctx, appID, name, description)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) GetRole(ctx context.Context, roleID uint) (*models.Role, error) {
	if m.GetRoleFunc != nil {
		return m.GetRoleFunc(ctx, roleID)
	}
	return nil, errors.New("not implemented")
}

func (m *MockAdminManager) UpdateRole(ctx context.Context, roleID uint, name, description string) error {
	if m.UpdateRoleFunc != nil {
		return m.UpdateRoleFunc(ctx, roleID, name, description)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) RemoveRole(ctx context.Context, roleID uint) error {
	if m.RemoveRoleFunc != nil {
		return m.RemoveRoleFunc(ctx, roleID)
	}
	return errors.New("not implemented")
}

func (m *MockAdminManager) CountUsers(ctx context.Context) (int64, error) {
	if m.CountUsersFunc != nil {
		return m.CountUsersFunc(ctx)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountApplications(ctx context.Context) (int64, error) {
	if m.CountApplicationsFunc != nil {
		return m.CountApplicationsFunc(ctx)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountActiveSessions(ctx context.Context) (int64, error) {
	if m.CountActiveSessionsFunc != nil {
		return m.CountActiveSessionsFunc(ctx)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountRoles(ctx context.Context) (int64, error) {
	if m.CountRolesFunc != nil {
		return m.CountRolesFunc(ctx)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountUsersCreatedAfter(ctx context.Context, after time.Time) (int64, error) {
	if m.CountUsersCreatedAfterFunc != nil {
		return m.CountUsersCreatedAfterFunc(ctx, after)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountApplicationsCreatedAfter(ctx context.Context, after time.Time) (int64, error) {
	if m.CountApplicationsCreatedAfterFunc != nil {
		return m.CountApplicationsCreatedAfterFunc(ctx, after)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountRolesCreatedAfter(ctx context.Context, after time.Time) (int64, error) {
	if m.CountRolesCreatedAfterFunc != nil {
		return m.CountRolesCreatedAfterFunc(ctx, after)
	}
	return 0, errors.New("not implemented")
}

func (m *MockAdminManager) CountSessionsCreatedAfter(ctx context.Context, after time.Time) (int64, error) {
	if m.CountSessionsCreatedAfterFunc != nil {
		return m.CountSessionsCreatedAfterFunc(ctx, after)
	}
	return 0, errors.New("not implemented")
}

// MockCache implements Cache for testing.
type MockCache struct {
	GetFunc  func(ctx context.Context, key string) ([]byte, error)
	SetFunc  func(ctx context.Context, key string, value []byte, ttl time.Duration) error
	GetHFunc func(ctx context.Context, key string, obj types.ObjInterface) error
	SetHFunc func(ctx context.Context, key string, value types.ObjInterface, ttl time.Duration) error
}

func (m *MockCache) Get(ctx context.Context, key string) ([]byte, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, key)
	}
	return nil, errors.New("not implemented")
}

func (m *MockCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if m.SetFunc != nil {
		return m.SetFunc(ctx, key, value, ttl)
	}
	return errors.New("not implemented")
}

func (m *MockCache) GetH(ctx context.Context, key string, obj types.ObjInterface) error {
	if m.GetHFunc != nil {
		return m.GetHFunc(ctx, key, obj)
	}
	return errors.New("not implemented")
}

func (m *MockCache) SetH(ctx context.Context, key string, value types.ObjInterface, ttl time.Duration) error {
	if m.SetHFunc != nil {
		return m.SetHFunc(ctx, key, value, ttl)
	}
	return errors.New("not implemented")
}

func newTestServer(t *testing.T, auth AuthManager, admin AdminManager, cache Cache) *Server {
	ctx := context.Background()
	log, err := logger.New(ctx, logger.SetEnableFileOutput(false), logger.SetEnableTerminalOutput(false))
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	srv := New(auth, admin, cache, log)
	// Set default options for testing
	srv.cookieDomain = []string{"localhost"}
	srv.cookieSecure = false
	srv.cookieLifeTime = 3600
	srv.jwtAccessTokenTTL = 900
	srv.jwtRefreshTokenTTL = 86400
	return srv
}

func TestHandlerLogin(t *testing.T) {
	auth := &MockAuthManager{}
	admin := &MockAdminManager{}
	cache := &MockCache{}
	srv := newTestServer(t, auth, admin, cache)

	// Сохраняем текущую директорию
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	// Переходим в корень проекта, где находятся templates
	err = os.Chdir("../../../..")
	if err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}
	defer os.Chdir(wd)

	// Отладочный вывод
	debugDir, _ := os.Getwd()
	t.Logf("Current directory: %s", debugDir)
	files, _ := filepath.Glob("templates/**/*")
	t.Logf("Found template files: %v", files)

	router := srv.SetupRouter()

	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", w.Code)
	}
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html content type, got %v", contentType)
	}
	body := w.Body.String()
	if !strings.Contains(body, "login") {
		t.Errorf("expected body to contain 'login', got %v", body)
	}
}

func TestHandlerAPILogin(t *testing.T) {
	auth := &MockAuthManager{}
	admin := &MockAdminManager{}
	cache := &MockCache{}
	srv := newTestServer(t, auth, admin, cache)

	// Генерируем реальный хеш для пароля "password"
	hashedPassword, err := authtools.HashPassword("password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Настройка моков
	auth.GetUserFunc = func(ctx context.Context, username string) (*models.User, error) {
		if username == "testuser" {
			return &models.User{
				Model: gorm.Model{
					ID: 1,
				},
				Login:        "testuser",
				PasswordHash: hashedPassword,
			}, nil
		}
		return nil, errors.New("user not found")
	}
	auth.CreateJWTFunc = func(data map[string]string) (string, error) {
		return "fake-jwt-token", nil
	}
	auth.GenRefreshTokenFunc = func(ctx context.Context, userID uint) (string, error) {
		return "fake-refresh-token", nil
	}
	cache.GetHFunc = func(ctx context.Context, key string, obj types.ObjInterface) error {
		return errors.New("not found")
	}
	cache.SetHFunc = func(ctx context.Context, key string, value types.ObjInterface, ttl time.Duration) error {
		return nil
	}

	// Успешный логин
	loginData := map[string]string{"username": "testuser", "password": "password"}
	body, _ := json.Marshal(loginData)
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	srv.handlerAPILogin(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", w.Code)
	}
	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if response["message"] != "Login successful" {
		t.Errorf("expected message 'Login successful', got %v", response["message"])
	}

	// Неверные учетные данные
	auth.GetUserFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, errors.New("user not found")
	}
	req = httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = req
	srv.handlerAPILogin(c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %v", w.Code)
	}
}

func TestHandlerLogut(t *testing.T) {
	auth := &MockAuthManager{}
	admin := &MockAdminManager{}
	cache := &MockCache{}
	srv := newTestServer(t, auth, admin, cache)

	// Настройка моков
	logoutCalled := false
	auth.LogoutFunc = func(ctx context.Context, refresh string) error {
		logoutCalled = true
		if refresh != "dummy-refresh" {
			t.Errorf("expected refresh token 'dummy-refresh', got %v", refresh)
		}
		return nil
	}

	// Создаём запрос с кукой refresh token
	req := httptest.NewRequest("GET", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  CookieRefreshToken,
		Value: "dummy-refresh",
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	srv.handlerLogut(c)

	// Проверяем статус редиректа (StatusTemporaryRedirect = 307)
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status TemporaryRedirect (307), got %v", w.Code)
	}
	// Проверяем, что LogoutFunc был вызван
	if !logoutCalled {
		t.Error("LogoutFunc was not called")
	}
	// Проверяем, что куки очищены
	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == CookieJWT || cookie.Name == CookieRefreshToken {
			if cookie.Value != "" && cookie.MaxAge != -1 {
				t.Errorf("cookie %s not cleared", cookie.Name)
			}
		}
	}
}
