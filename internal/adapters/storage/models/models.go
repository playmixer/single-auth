package models

import (
	"encoding/json"

	"gorm.io/gorm"
)

type User struct {
	Login        string `gorm:"index,idx_login,unique"`
	PasswordHash string
	Email        string `gorm:"index,idx_email,unique"`
	gorm.Model
}

func (u User) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

func (u *User) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, u)
}
