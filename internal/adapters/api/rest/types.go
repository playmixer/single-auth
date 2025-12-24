package rest

type tUser struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
