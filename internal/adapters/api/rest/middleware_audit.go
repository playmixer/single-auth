package rest

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/core/audit"
	"go.uber.org/zap"
)

// middlewareAudit создает middleware для логирования аудита
func (s *Server) middlewareAudit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем запрос, если аудит отключен
		if s.audit == nil {
			c.Next()
			return
		}

		// Засекаем время начала обработки
		start := time.Now()

		// Обрабатываем запрос
		c.Next()

		// После обработки запроса логируем
		duration := time.Since(start)

		// Извлекаем информацию о пользователе
		var userID *uint
		if uid, exists := c.Get("userID"); exists {
			if id, ok := uid.(uint); ok {
				userID = &id
			}
		}

		// IP и User-Agent
		ip := audit.ExtractIP(c.Request)
		userAgent := audit.ExtractUserAgent(c.Request)

		// Статус ответа
		status := "success"
		if c.Writer.Status() >= 400 {
			status = "failure"
		}

		// Детали запроса
		details := map[string]interface{}{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"query":      c.Request.URL.RawQuery,
			"statusCode": c.Writer.Status(),
			"duration":   duration.String(),
		}

		// Логируем в зависимости от пути
		action := getActionFromPath(c)
		resourceType := getResourceTypeFromPath(c)
		resourceID := getResourceIDFromParams(c)

		// Асинхронно записываем аудит
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var err error
			switch resourceType {
			case "user":
				if resourceID != "" {
					id, _ := strconv.ParseUint(resourceID, 10, 32)
					err = s.audit.LogUserEvent(ctx, userID, ip, userAgent, action, uint(id), details, status)
				} else {
					err = s.audit.LogAuthEvent(ctx, userID, ip, userAgent, action, details, status)
				}
			case "application":
				err = s.audit.LogApplicationEvent(ctx, userID, ip, userAgent, action, resourceID, details, status)
			case "role":
				if resourceID != "" {
					id, _ := strconv.ParseUint(resourceID, 10, 32)
					err = s.audit.LogRoleEvent(ctx, userID, ip, userAgent, action, uint(id), details, status)
				} else {
					err = s.audit.LogAuthEvent(ctx, userID, ip, userAgent, action, details, status)
				}
			default:
				err = s.audit.LogAuthEvent(ctx, userID, ip, userAgent, action, details, status)
			}
			if err != nil {
				s.log.Error("failed to write audit log", zap.Error(err))
			}
		}()
	}
}

// getActionFromPath определяет действие на основе пути и метода
func getActionFromPath(c *gin.Context) string {
	method := c.Request.Method
	path := c.FullPath()

	// Аутентификация
	if path == "/api/login" && method == "POST" {
		return "login"
	}
	if path == "/auth/logout" && method == "GET" {
		return "logout"
	}
	if path == "/profile/password" && method == "POST" {
		return "change_password"
	}

	// Админские действия
	if path == "/admin/users" && method == "POST" {
		return "user_create"
	}
	if path == "/admin/users/:userID/delete" && method == "POST" {
		return "user_delete"
	}
	if path == "/admin/users/:userID/update" && method == "POST" {
		return "user_update"
	}
	if path == "/admin/users/:userID/roles" && method == "POST" {
		return "user_roles_update"
	}
	if path == "/admin/applications" && method == "POST" {
		return "application_create"
	}
	if path == "/admin/applications/:appID/delete" && method == "POST" {
		return "application_delete"
	}
	if path == "/admin/applications/:appID/update" && method == "POST" {
		return "application_update"
	}
	if path == "/admin/applications/roles" && method == "POST" {
		return "role_create"
	}
	if path == "/admin/applications/roles/:roleID/edit" && method == "POST" {
		return "role_update"
	}
	if path == "/admin/applications/roles/:roleID/delete" && method == "POST" {
		return "role_delete"
	}

	// По умолчанию возвращаем метод + путь
	return method + "_" + path
}

// getResourceTypeFromPath определяет тип ресурса
func getResourceTypeFromPath(c *gin.Context) string {
	path := c.FullPath()

	switch {
	case contains(path, "/admin/users"):
		return "user"
	case contains(path, "/admin/applications"):
		if contains(path, "/roles") {
			return "role"
		}
		return "application"
	case contains(path, "/profile"):
		return "user"
	case contains(path, "/auth"):
		return "auth"
	default:
		return "system"
	}
}

// getResourceIDFromParams извлекает ID ресурса из параметров
func getResourceIDFromParams(c *gin.Context) string {
	if userID := c.Param("userID"); userID != "" {
		return userID
	}
	if appID := c.Param("appID"); appID != "" {
		return appID
	}
	if roleID := c.Param("roleID"); roleID != "" {
		return roleID
	}
	return ""
}

// contains проверяет наличие подстроки
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && s[:len(substr)] == substr)
}

// logAdminAction логирует админское действие синхронно (для важных операций)
func (s *Server) logAdminAction(c *gin.Context, action string, resourceType string, resourceID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}

	var userID *uint
	if uid, exists := c.Get("userID"); exists {
		if id, ok := uid.(uint); ok {
			userID = &id
		}
	}

	ip := audit.ExtractIP(c.Request)
	userAgent := audit.ExtractUserAgent(c.Request)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	var err error
	switch resourceType {
	case "user":
		id, _ := strconv.ParseUint(resourceID, 10, 32)
		err = s.audit.LogUserEvent(ctx, userID, ip, userAgent, action, uint(id), details, "success")
	case "application":
		err = s.audit.LogApplicationEvent(ctx, userID, ip, userAgent, action, resourceID, details, "success")
	case "role":
		id, _ := strconv.ParseUint(resourceID, 10, 32)
		err = s.audit.LogRoleEvent(ctx, userID, ip, userAgent, action, uint(id), details, "success")
	default:
		err = s.audit.LogAuthEvent(ctx, userID, ip, userAgent, action, details, "success")
	}

	if err != nil {
		s.log.Error("failed to log admin action", zap.Error(err))
	}
}
