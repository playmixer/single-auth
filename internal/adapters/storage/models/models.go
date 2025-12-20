package models

import (
	"gorm.io/gorm"
)

type User struct {
	Login        string `gorm:"index,idx_login,unique"`
	PasswordHash string
	Email        string `gorm:"index,idx_email,unique"`
	gorm.Model
}
