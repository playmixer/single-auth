package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	authtools "github.com/playmixer/single-auth/pkg/authtools"
	"github.com/playmixer/single-auth/pkg/logger"
)

type Store interface {
	GetUser(ctx context.Context, username string) (*models.User, error)
	CreateUser(ctx context.Context, username, email string, passwordHash string) (*models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)
}

type Auth struct {
	log       *logger.Logger
	secretKey []byte
	store     Store
	app       *ApplicationAuth
}

func New(log *logger.Logger, secretKey []byte, store Store) (*Auth, error) {
	return &Auth{
		store:     store,
		app:       InitApplicationAuthSettings(),
		secretKey: secretKey,
		log:       log,
	}, nil
}

func (a *Auth) GetUser(ctx context.Context, username string) (*models.User, error) {
	return a.store.GetUser(ctx, username)
}

func (a *Auth) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	return a.store.GetUserByID(ctx, userID)
}

func (a *Auth) GetPayloadUser(appID string, data map[string]string) (params, appLink string, err error) {
	app, err := a.app.GetAppByID(appID)
	if err != nil {
		return "", "", fmt.Errorf("application not registered: %w", err)
	}

	appLink = app.AuthLink
	bParams, err := json.Marshal(data)
	if err != nil {
		return "", "", fmt.Errorf("failed marshal data: %w", err)
	}
	params = base64.RawStdEncoding.EncodeToString(bParams)

	return params, appLink, err
}

// VerifyJWT - Проверяет JWT.
func (a *Auth) VerifyJWT(signedData string) (map[string]string, bool) {
	return authtools.VerifyJWT(a.secretKey, signedData)
}

// CreateJWT - Создает JWT ключ и записывает в него ID пользователя.
func (a *Auth) CreateJWT(data map[string]string) (string, error) {
	return authtools.CreateJWT(a.secretKey, data)
}
