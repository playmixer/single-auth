package rest

import (
	"auth/internal/adapters/types"
	"auth/pkg/utils"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (s *Server) handlerLogin(c *gin.Context) {
	var err error
	var userID string
	isAuth := false
	var user *types.User
	userID, err = s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
	}
	if err == nil {
		isAuth = true
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"status": "ok",
		"isAuth": isAuth,
		"user":   user,
	})
}

func (s *Server) handlerAPILogin(c *gin.Context) {
	var err error
	type tUser struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var data tUser
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user := &types.User{}
	if user, err = s.auth.GetUser(c.Request.Context(), data.Username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user data"})
		return
	}

	// Сравниваем введённый пароль с хэшем
	if ok := utils.CheckPasswordHash(user.PasswordHash, data.Password); !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect username or password"})
		return
	}

	token, err := s.auth.CreateJWT(map[string]string{
		"userID": strconv.Itoa(int(user.ID)),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed create token"})
		return
	}
	c.SetCookie(CookieNameToken, token, 0, "/", c.Request.Host, true, true)

	// Если всё прошло успешно
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		// "token":   token,
	})
}

func (s *Server) handlerLogut(c *gin.Context) {
	c.SetCookie(CookieNameToken, "", 0, "/", c.Request.Host, true, true)

	c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
}

func (s *Server) handlerAPIUserAuthInfo(c *gin.Context) {
	var err error
	var userID string
	var user *types.User
	userID, err = s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
			return
		}
	}

	cookie, _ := c.Request.Cookie(CookieNameToken)
	params, appLink, err := s.auth.GetPayloadUser(c.Query("appID"), map[string]string{
		"username": user.Username,
		"email":    user.Email,
		"token":    cookie.Value,
	})
	if err != nil {
		s.log.Error("failed generate app params", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "failed generate app params",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"params":  params,
		"appLink": appLink,
	})
}
