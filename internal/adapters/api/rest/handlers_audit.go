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

// handlerMetrics возвращает метрики аудита и системных логов
func (s *Server) handlerMetrics(c *gin.Context) {
	if s.audit == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service unavailable"})
		return
	}

	ctx := c.Request.Context()

	// Парсинг параметров периода
	fromStr := c.Query("from")
	toStr := c.Query("to")
	hoursStr := c.Query("hours")
	limitStr := c.Query("limit")

	// По умолчанию: последние 24 часа
	defaultFrom := time.Now().Add(-24 * time.Hour)
	defaultTo := time.Now()

	var from, to time.Time
	if fromStr != "" {
		parsed, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from date"})
			return
		}
		from = parsed
	} else {
		from = defaultFrom
	}

	if toStr != "" {
		parsed, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to date"})
			return
		}
		to = parsed
	} else {
		to = defaultTo
	}

	// Количество часов для временного ряда активности
	hours := 24
	if hoursStr != "" {
		h, err := strconv.Atoi(hoursStr)
		if err != nil || h < 1 || h > 720 { // максимум 30 дней
			c.JSON(http.StatusBadRequest, gin.H{"error": "hours must be between 1 and 720"})
			return
		}
		hours = h
	}

	// Лимит для топа пользователей
	limit := 10
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil || l < 1 || l > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 100"})
			return
		}
		limit = l
	}

	// Получение метрик аудита
	auditMetrics, err := s.audit.GetAuditMetrics(ctx, from, to)
	if err != nil {
		s.log.Error("failed to get audit metrics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve audit metrics"})
		return
	}

	// Получение метрик системных логов
	systemMetrics, err := s.audit.GetSystemMetrics(ctx, from, to)
	if err != nil {
		s.log.Error("failed to get system metrics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve system metrics"})
		return
	}

	// Получение временного ряда активности
	activity, err := s.audit.GetAuditActivityByHour(ctx, hours)
	if err != nil {
		s.log.Error("failed to get audit activity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve activity"})
		return
	}

	// Получение топа пользователей
	topUsers, err := s.audit.GetTopUsers(ctx, limit)
	if err != nil {
		s.log.Error("failed to get top users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve top users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"audit_metrics":    auditMetrics,
		"system_metrics":   systemMetrics,
		"activity_by_hour": activity,
		"top_users":        topUsers,
		"period": gin.H{
			"from": from,
			"to":   to,
		},
		"hours": hours,
		"limit": limit,
	})
}

// handlerAuditPage отображает страницу аудита
func (s *Server) handlerAuditPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/audit_logs.html", gin.H{
		"Title":        "Аудит логи",
		"ActiveTab":    "audit",
		"ContentBlock": "content_audit",
		"HeaderTitle":  "Аудит логи",
	})
}

// handlerMetricsPage отображает страницу метрик
func (s *Server) handlerMetricsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/metrics.html", gin.H{
		"Title":        "Метрики аудита",
		"ActiveTab":    "metrics",
		"ContentBlock": "content_metrics",
		"HeaderTitle":  "Метрики аудита",
	})
}

// handlerSystemLogsPage отображает страницу системных логов
func (s *Server) handlerSystemLogsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/system_logs.html", gin.H{
		"Title":        "Системные логи",
		"ActiveTab":    "system",
		"ContentBlock": "content_system",
		"HeaderTitle":  "Системные логи",
	})
}
