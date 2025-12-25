package admin

import (
	"context"
	"fmt"

	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/pkg/logger"
)

type Store interface {
	FindUsersByLogin(ctx context.Context, login string) ([]models.User, error)
	CreateUser(ctx context.Context, username string, email string, passwordHash string) (*models.User, error)
	GetUser(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)
	RemoveUser(ctx context.Context, userID uint) error
	UpdUser(ctx context.Context, user *models.User) error

	CreateApplication(ctx context.Context, title, link string) (*models.Application, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	GetApplicationByTitle(ctx context.Context, title string) (*models.Application, error)
	UpdateApplication(ctx context.Context, app *models.Application) error
	RemoveApplication(ctx context.Context, appID string) error
	FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error)
}

type AdminPanel struct {
	store Store
}

func New(store Store, log *logger.Logger) *AdminPanel {
	a := &AdminPanel{
		store: store,
	}

	return a
}

func (a *AdminPanel) FindUsersByLogin(ctx context.Context, login string) ([]models.User, error) {
	return a.store.FindUsersByLogin(ctx, login)
}

func (a *AdminPanel) CreateNewUser(ctx context.Context, login, email, passwordHash string) (*models.User, error) {
	if _, err := a.store.GetUser(ctx, login); err == nil {
		return nil, fmt.Errorf("user `%s` is existed: %w", login, err)
	}
	return a.store.CreateUser(ctx, login, email, passwordHash)
}

func (a *AdminPanel) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	return a.store.GetUserByID(ctx, userID)
}

func (a *AdminPanel) RemoveUser(ctx context.Context, userID uint) error {
	return a.store.RemoveUser(ctx, userID)
}

func (a *AdminPanel) UpdUser(ctx context.Context, user *models.User) error {
	return a.store.UpdUser(ctx, user)
}

func (a *AdminPanel) CreateApplication(ctx context.Context, title, link string) (*models.Application, error) {
	app, err := a.store.GetApplicationByTitle(ctx, title)
	if err == nil {
		return app, fmt.Errorf("application `%s` is exist", title)
	}

	return a.store.CreateApplication(ctx, title, link)
}

func (a *AdminPanel) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	app, err := a.store.GetApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("failed get application: %w", err)
	}

	return app, nil
}

func (a *AdminPanel) UpdateApplication(ctx context.Context, app *models.Application) error {
	return a.store.UpdateApplication(ctx, app)
}

func (a *AdminPanel) RemoveApplication(ctx context.Context, appID string) error {
	return a.store.RemoveApplication(ctx, appID)
}

func (a *AdminPanel) FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error) {
	return a.store.FindApplicationByTitle(ctx, title)
}
