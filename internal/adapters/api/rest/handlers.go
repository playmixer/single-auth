package rest

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/apperror"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/pkg/authtools"
	"go.uber.org/zap"
)

func (s *Server) handlerLogin(c *gin.Context) {
	s.middlewareCheckCookies()(c)
	isAuth, user, _ := s.isAuthenticate(c)

	c.HTML(http.StatusOK, "user/login.html", gin.H{
		"status": "ok",
		"isAuth": isAuth,
		"user":   user,
	})
}

func (s *Server) handlerAPILogin(c *gin.Context) {
	var err error

	var data tUser
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user := &models.User{}
	key := "user:" + data.Username
	if err = s.cache.GetH(c.Request.Context(), key, user); err != nil {
		if user, err = s.auth.GetUser(c.Request.Context(), data.Username); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user data"})
			return
		}

		err = s.cache.SetH(c.Request.Context(), key, user, time.Second*30)
		if err != nil {
			s.log.Error("failed save to cache", zap.String("key", key), zap.Error(err))
		}
	}
	s.log.Debug("get user", zap.Any("user", *user))

	// Сравниваем введённый пароль с хэшем
	if ok := authtools.CheckPasswordHash(user.PasswordHash, data.Password); !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect username or password"})
		return
	}

	token, err := s.auth.CreateJWT(map[string]string{
		"userID":      strconv.Itoa(int(user.ID)),
		"isAdmin":     strconv.FormatBool(user.IsAdmin),
		"expiredUnix": strconv.FormatInt(time.Now().Unix()+int64(s.jwtAccessTokenTTL), 10),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed create token",
			"message": err.Error(),
		})
		return
	}
	refresh, err := s.auth.GenRefreshToken(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed create token",
			"message": err.Error(),
		})
		return
	}
	for _, domain := range s.cookieDomain {
		s.log.Debug("save cookie", zap.String("host", domain), zap.String("token", token), zap.String("refresh", refresh))
		c.SetCookie(CookieJWT, token, s.cookieLifeTime, "/", domain, s.cookieSecure, true)
		c.SetCookie(CookieRefreshToken, refresh, s.cookieLifeTime, "/", domain, s.cookieSecure, true)
	}
	// Если всё прошло успешно
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		// "token":   token,
	})
}

func (s *Server) handlerLogut(c *gin.Context) {
	userRefresh, err := c.Request.Cookie(CookieRefreshToken)
	if err != nil {
		s.log.Error("failed get cookie refresh", zap.Error(err))
	}
	if err == nil && userRefresh.Value != "" {
		go func(refresh string) {
			err = s.auth.Logout(context.Background(), refresh)
			if err != nil {
				s.log.Error("failed logout", zap.Error(err), zap.String("refresh", refresh))
				return
			}
		}(userRefresh.Value)
	}

	for _, domain := range s.cookieDomain {
		c.SetCookie(CookieJWT, "", s.cookieLifeTime, "/", domain, s.cookieSecure, true)
		c.SetCookie(CookieRefreshToken, "", s.cookieLifeTime, "/", domain, s.cookieSecure, true)
	}

	c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
}

func (s *Server) handlerAPIUserAuthInfo(c *gin.Context) {
	var err error
	var user *models.User
	_, user, err = s.isAuthenticate(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized",
		})
		return
	}

	s.log.Debug("user info", zap.Any("user", *user))

	appID := c.Query("appID")
	if empty(appID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appID not valid",
		})
		return
	}

	roles := []string{}
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	// cookie, _ := c.Request.Cookie(CookieJWT)
	key := "apppayload:appid:" + appID + ":user:" + strconv.Itoa(int(user.ID))
	payload := &Payload{}
	if err := s.cache.GetH(c.Request.Context(), key, payload); err != nil {
		payload.Params, payload.Link, err = s.auth.GetPayloadUser(c.Request.Context(), appID, map[string]string{
			"username": user.Login,
			"email":    user.Email,
			// "token":    cookie.Value,
			"roles": strings.Join(roles, ","),
		})
		if err != nil {
			s.log.Error("failed generate app params", zap.Error(err), zap.String("appID", appID))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "failed generate app params",
				"message": err.Error(),
			})
			return
		}
		if err := s.cache.SetH(c.Request.Context(), key, payload, ttlCacheDefault); err != nil {
			s.log.Error("failed cache app params", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"params":  payload.Params,
		"appLink": payload.Link,
	})
}

func (s *Server) handlerUserProfile(c *gin.Context) {
	isAuth, user, _ := s.isAuthenticate(c)

	c.HTML(http.StatusOK, "user/profile.html", gin.H{
		"status": "ok",
		"isAuth": isAuth,
		"user":   user,
	})
}

func (s *Server) handlerUserProfileChangePassword(c *gin.Context) {
	var err error
	_, user, _ := s.isAuthenticate(c)
	passCur := c.PostForm("current_password")
	passNew := c.PostForm("new_password")
	passNew2 := c.PostForm("confirm_password")

	if !authtools.CheckPasswordHash(user.PasswordHash, passCur) {
		c.Redirect(http.StatusMovedPermanently, "/profile?error=incorrect_current_password")
		return
	}
	if authtools.CheckPasswordHash(user.PasswordHash, passNew) {
		c.Redirect(http.StatusMovedPermanently, "/profile?error=new_password_is_equal_new_password")
		return
	}
	if passNew != passNew2 {
		c.Redirect(http.StatusMovedPermanently, "/profile?error=new_passwored_not_equal")
		return
	}
	user.PasswordHash, err = authtools.HashPassword(passNew)
	if err != nil {
		s.log.Error("failed hashing password", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/profile?error=incorrect_password")
		return
	}
	err = s.auth.UpdUser(c.Request.Context(), user)
	if err != nil {
		s.log.Error("failed update user", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/profile?error=failed_update_password")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/profile")
}

func (s *Server) handlerAdmin(c *gin.Context) {
	isAuth, user, _ := s.isAuthenticate(c)

	c.HTML(http.StatusOK, "admin/index.html", gin.H{
		"status": "ok",
		"isAuth": isAuth,
		"user":   user,
	})
}

func (s *Server) handlerAdminUsers(c *gin.Context) {
	var err error
	isAuth, user, _ := s.isAuthenticate(c)
	errMessage := c.Query("error")

	search := c.Query("search_query")
	searchUsers := models.Users{}
	if search != "" {
		searchUsers, err = s.admin.FindUsersByLogin(c.Request.Context(), search)
		if err != nil {
			errMessage = "failed search users"
			s.log.Error("failed search users", zap.Error(err))
		}
	}

	applications, err := s.admin.FindApplicationByTitle(c.Request.Context(), "")
	if err != nil {
		errMessage = "failed find applications"
		s.log.Error("failed find applications", zap.Error(err))
	}

	c.HTML(http.StatusOK, "admin/users.html", gin.H{
		"status":       "ok",
		"isAuth":       isAuth,
		"user":         user,
		"users":        searchUsers,
		"applications": applications,
		"error":        errMessage,
		"search":       search,
	})
}

func (s *Server) handlerAdminNewUser(c *gin.Context) {
	login := strings.ToLower(c.PostForm("login"))
	email := strings.ToLower(c.PostForm("email"))
	password := c.PostForm("password")
	password2 := c.PostForm("password2")
	adminS := c.PostForm("admin")
	admin := adminS == "on"

	if empty(login) || empty(email) || empty(password) || empty(password2) {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=not_valid_datas")
		return
	}

	if password != password2 {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=password_not_equale")
		return
	}

	passwordHash, err := authtools.HashPassword(password)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=failed_to_hash_password")
		return
	}

	_, err = s.admin.CreateNewUser(c.Request.Context(), login, email, passwordHash, admin)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=failed_create_user")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/admin/users?search_query="+login)
}

func (s *Server) handlerAdminRemoveUser(c *gin.Context) {
	userIDs := c.Param("userID")
	userID, err := strconv.ParseUint(userIDs, 10, 32)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error="+err.Error())
		return
	}

	user, err := s.admin.GetUserByID(c.Request.Context(), uint(userID))
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=user_not_found")
		return
	}

	err = s.admin.RemoveUser(c.Request.Context(), user.ID)
	if err != nil {
		s.log.Error("failed remove user", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=failed_remove_user")
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/admin/users?search_query="+user.Login)
}

func (s *Server) handlerAdminUpdUser(c *gin.Context) {
	var err error
	var passwordHash string
	email := c.PostForm("email")
	login := c.PostForm("login")
	password := c.PostForm("password")
	password2 := c.PostForm("password2")
	adminS := c.PostForm("admin")
	admin := adminS == "on"

	if empty(email) {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=not_valid_email&search_query="+login)
		return
	}
	if !empty(password) || !empty(password2) {
		if password != password2 {
			c.Redirect(http.StatusMovedPermanently, "/admin/users?error=password_not_equale&search_query="+login)
			return
		}

		passwordHash, err = authtools.HashPassword(password)
		if err != nil {
			c.Redirect(http.StatusMovedPermanently, "/admin/users?error=failed_to_hash_password&search_query="+login)
			return
		}
	}

	userIDs := c.Param("userID")
	userID, err := strconv.ParseUint(userIDs, 10, 32)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=user_id_not_valid&search_query="+login)
		return
	}

	user, err := s.admin.GetUserByID(c.Request.Context(), uint(userID))
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=user_not_found")
		return
	}

	if passwordHash != "" {
		user.PasswordHash = passwordHash
	}
	user.Email = email
	user.IsAdmin = admin

	err = s.admin.UpdUser(c.Request.Context(), user)
	if err != nil {
		s.log.Error("failed update user", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=faile_update_user")
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/admin/users?search_query="+user.Login)
}

func (s *Server) handlerAdminUprRolesUser(c *gin.Context) {
	sRoles := c.PostFormArray("roles")
	userIDs := c.Param("userID")
	userID, err := strconv.ParseUint(userIDs, 10, 32)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=user_id_not_valid")
		return
	}

	user, err := s.admin.GetUserByID(c.Request.Context(), uint(userID))
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=user_not_found")
		return
	}

	roles, err := arrString(sRoles).StringSliceToUintSlice()
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=roles_not_valid")
		return
	}

	s.log.Debug("upd roles", zap.Any("user", user), zap.Any("roles", roles))
	err = s.admin.UpdRolesUser(c.Request.Context(), user.ID, roles)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/users?error=failed_upd_user_roles")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/admin/users?search_query="+user.Login)
}

func (s *Server) handlerAdminApplications(c *gin.Context) {
	var err error
	isAuth, user, _ := s.isAuthenticate(c)
	errMessage := c.Query("error")
	search := c.Query("search_query")

	apps := []models.Application{}
	if search != "" {
		apps, err = s.admin.FindApplicationByTitle(c.Request.Context(), search)
		if err != nil {
			s.log.Error("failed find applications", zap.Error(err))
			errMessage = "failed find applications"
		}
	}

	c.HTML(http.StatusOK, "admin/applications.html", gin.H{
		"status":       "ok",
		"isAuth":       isAuth,
		"user":         user,
		"search":       search,
		"error":        errMessage,
		"applications": apps,
		"baseURL":      s.baseURL,
	})
}

func (s *Server) handlerAdminApplicationNew(c *gin.Context) {
	title := c.PostForm("title")
	link := c.PostForm("link")

	_, err := s.admin.CreateApplication(c.Request.Context(), title, link)
	if err != nil {
		s.log.Error("failed create application", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=faile_create_application")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/admin/applications?search_query="+title)
}

func (s *Server) handlerAdminRemoveApplication(c *gin.Context) {
	appID := c.Param("appID")

	app, err := s.admin.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=application_not_found")
		return
	}

	err = s.admin.RemoveApplication(c.Request.Context(), app.ID.String())
	if err != nil {
		s.log.Error("failed remove applications", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=failed_remove_application")
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/admin/applications?search_query="+app.Title)
}

func (s *Server) handlerAdminUpdApplication(c *gin.Context) {
	var err error
	title := c.PostForm("title")
	link := c.PostForm("link")

	if empty(title) || empty(link) {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=not_valid_data&search_query="+title)
		return
	}

	appID := c.Param("appID")

	app, err := s.admin.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=user_not_found")
		return
	}

	app.Title = title
	app.AuthLink = link

	err = s.admin.UpdateApplication(c.Request.Context(), app)
	if err != nil {
		s.log.Error("failed update user", zap.Error(err))
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=faile_update_user")
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/admin/applications?search_query="+app.Title)
}

func (s *Server) handlerAdminApplicationRoles(c *gin.Context) {
	var err error
	errMessage := c.Query("error")
	appID := c.Query("appID")
	app, err := s.admin.GetApplication(c.Request.Context(), appID)
	if err != nil {
		if errors.Is(err, apperror.ErrNotFoundData) {
			c.HTML(http.StatusNotFound, "error/404.html", gin.H{
				"error": "application_not_found",
			})
			return
		}
		c.HTML(http.StatusInternalServerError, "admin/application_roles.html", gin.H{
			"error": "failed_getting_application",
		})
		return
	}

	s.log.Debug("app", zap.Any("app", app))

	c.HTML(http.StatusOK, "admin/application_roles.html", gin.H{
		"app":     app,
		"baseURL": s.baseURL,
		"error":   errMessage,
	})
}

func (s *Server) handlerAdminApplicationRolesNew(c *gin.Context) {
	appID := c.PostForm("appID")
	if appID == "" {
		c.HTML(http.StatusNotFound, "error/404.html", gin.H{
			"error": "application_not_found",
		})
		return
	}

	name := c.PostForm("role_name")
	description := c.PostForm("role_description")

	_, err := s.admin.CreateRoleApplication(c.Copy().Request.Context(), appID, name, description)
	if err != nil {
		if errors.Is(err, apperror.ErrNotFoundData) {
			c.HTML(http.StatusNotFound, "error/404.html", gin.H{
				"error": "application_not_found",
			})
			return
		}
		c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID+"&error=faile_create_role")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID)
}

func (s *Server) handlerAdminApplicationUpdRole(c *gin.Context) {
	appID := c.PostForm("appID")
	if appID == "" {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=app_id_not_valid")
		return
	}
	_, err := s.admin.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications?error=app_not_valid")
		return
	}
	roleIDs := c.Param("roleID")
	roleID, err := strconv.ParseUint(roleIDs, 10, 32)
	if err != nil {

	}
	if roleID == 0 || c.Param("roleID") != c.PostForm("roleID") {
		c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID+"&error=role_id_not_valid")
		return
	}

	name := c.PostForm("edit_role_name")
	description := c.PostForm("edit_role_description")

	err = s.admin.UpdateRole(c.Copy().Request.Context(), uint(roleID), name, description)
	if err != nil {
		if errors.Is(err, apperror.ErrNotFoundData) {
			c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID+"&error=role_not_found")
			return
		}
		c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID+"&error=faile_create_role")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/admin/applications/roles?appID="+appID)
}
