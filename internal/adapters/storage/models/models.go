package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	Login        string `gorm:"index,idx_login,unique"`
	PasswordHash string
	Email        string `gorm:"index,idx_email,unique"`
	Roles        []Role `gorm:"many2many:user_roles;"`
	IsAdmin      bool
	gorm.Model
}

func (u User) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

func (u *User) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, u)
}

type Users []User

func (us Users) MarshalBinary() ([]byte, error) {
	return json.Marshal(us)
}

func (us *Users) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, us)
}

type Application struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key"`
	Title     string    `gorm:"index,idx_app_title,unique"`
	AuthLink  string
	Roles     []Role
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (a *Application) BeforeCreate(tx *gorm.DB) (err error) {
	a.ID = uuid.New()
	return
}

type Session struct {
	ID          uint   `gorm:"primarykey"`
	Token       string `gorm:"index,idx_token,unique"`
	User        User
	UserID      uint `gorm:"index,idx_session_user"`
	ExpiredDate time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Role struct {
	ID          uint   `gorm:"primarykey"`
	Name        string `gorm:"index,idx_role_name,unique"`
	Description string
	// Application   Application
	ApplicationID uuid.UUID `gorm:"not null,index,idx_role_application"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
