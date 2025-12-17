package types

import "time"

type User struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}
