package rest

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/audit"
	"go.uber.org/zap"
)

// handlerAuditLogs возвращает список записей аудита
func (s *Server) handlerAuditLogs(c *gin.Context) {
	if s.audit == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service unavailable"})
		return
	}

	// Парсинг параметров запроса
	userIDStr := c.Query("user_id")
	action := c.Query("action")
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")
	status := c.Query("status")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")
	category := c.Query("category")

	filter := audit.AuditFilter{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Status:       status,
	}

	// Обработка категории
	if category != "" {
		switch category {
		case "auth":
			filter.ResourceTypes = []string{"auth"}
			filter.ResourceType = "" // очищаем, чтобы не конфликтовало
		case "admin":
			filter.ResourceTypes = []string{"user", "application", "role", "system"}
			filter.ResourceType = ""
		case "all":
			// оставляем оба пустыми, чтобы выбрать все типы
			filter.ResourceType = ""
		default:
			// неизвестная категория - игнорируем
		}
	}

	// UserID
	if userIDStr != "" {
		uid, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
			return
		}
		userID := uint(uid)
		filter.UserID = &userID
	}

	// From
	if fromStr != "" {
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from date"})
			return
		}
		filter.From = from
	}

	// To
	if toStr != "" {
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to date"})
			return
		}
		filter.To = to
	}

	// Limit
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 1000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 1000"})
			return
		}
		filter.Limit = limit
	} else {
		filter.Limit = 100
	}

	// Offset
	if offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid offset"})
			return
		}
		filter.Offset = offset
	}

	logs, err := s.audit.GetAuditLogs(c.Request.Context(), filter)
	if err != nil {
		s.log.Error("failed to get audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Debug log
	if len(logs) > 0 {
		s.log.Debug("first audit log", zap.Any("log", logs[0]), zap.String("timestamp", logs[0].Timestamp.String()))
	}
	s.log.Debug("audit logs response", zap.Any("logs", logs), zap.Int("total", len(logs)))

	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"meta": gin.H{
			"total":  len(logs),
			"limit":  filter.Limit,
			"offset": filter.Offset,
		},
	})
}

// handlerSystemLogs возвращает системные логи
func (s *Server) handlerSystemLogs(c *gin.Context) {
	if s.audit == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service unavailable"})
		return
	}

	level := c.Query("level")
	component := c.Query("component")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")

	filter := audit.SystemFilter{
		Level:     level,
		Component: component,
	}

	// From
	if fromStr != "" {
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from date"})
			return
		}
		filter.From = from
	}

	// To
	if toStr != "" {
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to date"})
			return
		}
		filter.To = to
	}

	// Limit
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 1000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 1000"})
			return
		}
		filter.Limit = limit
	} else {
		filter.Limit = 100
	}

	// Offset
	if offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid offset"})
			return
		}
		filter.Offset = offset
	}

	logs, err := s.audit.GetSystemLogs(c.Request.Context(), filter)
	if err != nil {
		s.log.Error("failed to get system logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"meta": gin.H{
			"total":  len(logs),
			"limit":  filter.Limit,
			"offset": filter.Offset,
		},
	})
}

// handlerAuditExport экспортирует аудит логи в CSV (заглушка)
func (s *Server) handlerAuditExport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "export not implemented yet"})
}

// handlerMetrics возвращает метрики (заглушка)
func (s *Server) handlerMetrics(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "metrics not implemented yet"})
}

// handlerAuditPage отображает страницу аудита
func (s *Server) handlerAuditPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/audit_logs.html", gin.H{
		"title": "Аудит логи",
	})
}
