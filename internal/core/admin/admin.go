package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/pkg/logger"
	"github.com/playmixer/single-auth/pkg/utils"
)

type Store interface {
	FindUsersByLogin(ctx context.Context, login string) ([]models.User, error)
	CreateUser(ctx context.Context, username string, email string, passwordHash string, admin bool) (*models.User, error)
	GetUser(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)
	RemoveUser(ctx context.Context, userID uint) error
	UpdUser(ctx context.Context, user *models.User) error
	UpdUserRoles(ctx context.Context, user *models.User, roles []models.Role) error

	CreateApplication(ctx context.Context, title, link string) (*models.Application, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	GetApplicationByTitle(ctx context.Context, title string) (*models.Application, error)
	UpdateApplication(ctx context.Context, app *models.Application) error
	RemoveApplication(ctx context.Context, appID string) error
	FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error)
	CreateRole(ctx context.Context, appID, name, description string) (*models.Role, error)
	UpdRole(ctx context.Context, role *models.Role) error
	GetRole(ctx context.Context, roleID uint) (*models.Role, error)
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

func (a *AdminPanel) CreateNewUser(ctx context.Context, login, email, passwordHash string, admin bool) (*models.User, error) {
	if _, err := a.store.GetUser(ctx, login); err == nil {
		return nil, fmt.Errorf("user `%s` is existed: %w", login, err)
	}
	return a.store.CreateUser(ctx, login, email, passwordHash, admin)
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

func (a *AdminPanel) CreateRoleApplication(ctx context.Context, appID string, name string, description string) (*models.Role, error) {
	// оставляем только цифры и латиницу
	name = utils.FilterAlphaNumeric(name)
	if name == "" {
		return nil, errors.New("role name not valid")
	}
	app, err := a.store.GetApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("failed getting application: %w", err)
	}

	// убираем лишние пробелы и меняем на заглавные
	name = strings.ToUpper(name)

	role, err := a.store.CreateRole(ctx, app.ID.String(), name, description)
	if err != nil {
		return nil, fmt.Errorf("failed create role: %w", err)
	}

	return role, nil
}

func (a *AdminPanel) UpdateRole(ctx context.Context, roleID uint, name, description string) error {
	// оставляем только цифры и латиницу
	name = utils.FilterAlphaNumeric(name)
	if name == "" {
		return errors.New("role name not valid")
	}

	role, err := a.store.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed getting role: %w", err)
	}

	// убираем лишние пробелы и меняем на заглавные
	name = strings.ToUpper(name)
	role.Name = name
	role.Description = description
	return a.store.UpdRole(ctx, role)
}

func (a *AdminPanel) UpdRolesUser(ctx context.Context, userID uint, roleIDs []uint) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed getting user: %w", err)
	}

	roles := make([]models.Role, 0)
	for _, id := range roleIDs {
		role, err := a.store.GetRole(ctx, id)
		if err != nil {
			return fmt.Errorf("failed getting role `%v`: %w", id, err)
		}

		roles = append(roles, *role)
	}

	err = a.store.UpdUserRoles(ctx, user, roles)
	if err != nil {
		return fmt.Errorf("failed update user roles: %w", err)
	}

	return nil
}
