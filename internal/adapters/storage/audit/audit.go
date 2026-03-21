package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"gorm.io/gorm"
)

// Store определяет интерфейс для работы с аудитом
type Store interface {
	CreateAuditLog(ctx context.Context, log *models.AuditLog) error
	FindAuditLogs(ctx context.Context, filter AuditFilter) ([]models.AuditLog, error)
	CreateSystemLog(ctx context.Context, log *models.SystemLog) error
	FindSystemLogs(ctx context.Context, filter SystemFilter) ([]models.SystemLog, error)
	GetAuditMetrics(ctx context.Context, from, to time.Time) (*AuditMetrics, error)
	GetSystemMetrics(ctx context.Context, from, to time.Time) (*SystemMetrics, error)
	GetAuditActivityByHour(ctx context.Context, hours int) ([]TimeSeriesPoint, error)
	GetTopUsers(ctx context.Context, limit int) ([]TopUser, error)
}

// AuditFilter параметры фильтрации аудита
type AuditFilter struct {
	UserID        *uint
	Action        string
	ResourceType  string
	ResourceTypes []string
	ResourceID    string
	Status        string
	From          time.Time
	To            time.Time
	Limit         int
	Offset        int
}

// SystemFilter параметры фильтрации системных логов
type SystemFilter struct {
	Level     string
	Component string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

// AuditMetrics содержит агрегированные метрики аудита
type AuditMetrics struct {
	Total      int64            `json:"total"`
	ByStatus   map[string]int64 `json:"by_status"`
	ByResource map[string]int64 `json:"by_resource"`
	ByAction   map[string]int64 `json:"by_action"`
}

// SystemMetrics содержит агрегированные метрики системных логов
type SystemMetrics struct {
	Total       int64            `json:"total"`
	ByLevel     map[string]int64 `json:"by_level"`
	ByComponent map[string]int64 `json:"by_component"`
}

// TimeSeriesPoint представляет точку временного ряда
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

// TopUser представляет пользователя и количество его действий
type TopUser struct {
	UserID *uint `json:"user_id"`
	Count  int64 `json:"count"`
}

type store struct {
	db *gorm.DB
}

// New создает новое хранилище аудита
func New(db *gorm.DB) Store {
	return &store{db: db}
}

// CreateAuditLog создает запись аудита
func (s *store) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return s.db.WithContext(ctx).Create(log).Error
}

// FindAuditLogs ищет записи аудита по фильтру
func (s *store) FindAuditLogs(ctx context.Context, filter AuditFilter) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	query := s.db.WithContext(ctx).Model(&models.AuditLog{})

	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if len(filter.ResourceTypes) > 0 {
		query = query.Where("resource_type IN ?", filter.ResourceTypes)
	} else if filter.ResourceType != "" {
		query = query.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		query = query.Where("resource_id = ?", filter.ResourceID)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if !filter.From.IsZero() {
		query = query.Where("timestamp >= ?", filter.From)
	}
	if !filter.To.IsZero() {
		query = query.Where("timestamp <= ?", filter.To)
	}

	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	err := query.Order("timestamp DESC").Find(&logs).Error
	return logs, err
}

// CreateSystemLog создает системную запись лога
func (s *store) CreateSystemLog(ctx context.Context, log *models.SystemLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	return s.db.WithContext(ctx).Create(log).Error
}

// FindSystemLogs ищет системные логи по фильтру
func (s *store) FindSystemLogs(ctx context.Context, filter SystemFilter) ([]models.SystemLog, error) {
	var logs []models.SystemLog
	query := s.db.WithContext(ctx).Model(&models.SystemLog{})

	if filter.Level != "" {
		query = query.Where("level = ?", filter.Level)
	}
	if filter.Component != "" {
		query = query.Where("component = ?", filter.Component)
	}
	if !filter.From.IsZero() {
		query = query.Where("timestamp >= ?", filter.From)
	}
	if !filter.To.IsZero() {
		query = query.Where("timestamp <= ?", filter.To)
	}

	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	err := query.Order("timestamp DESC").Find(&logs).Error
	return logs, err
}

// GetAuditMetrics возвращает агрегированные метрики аудита за период
func (s *store) GetAuditMetrics(ctx context.Context, from, to time.Time) (*AuditMetrics, error) {
	metrics := &AuditMetrics{
		ByStatus:   make(map[string]int64),
		ByResource: make(map[string]int64),
		ByAction:   make(map[string]int64),
	}

	// Общее количество
	var total int64
	err := s.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Count(&total).Error
	if err != nil {
		return nil, err
	}
	metrics.Total = total

	// Группировка по статусу
	type statusCount struct {
		Status string
		Count  int64
	}
	var statusCounts []statusCount
	err = s.db.WithContext(ctx).Model(&models.AuditLog{}).
		Select("status, COUNT(*) as count").
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Group("status").
		Scan(&statusCounts).Error
	if err != nil {
		return nil, err
	}
	for _, sc := range statusCounts {
		metrics.ByStatus[sc.Status] = sc.Count
	}

	// Группировка по resource_type
	type resourceCount struct {
		ResourceType string
		Count        int64
	}
	var resourceCounts []resourceCount
	err = s.db.WithContext(ctx).Model(&models.AuditLog{}).
		Select("resource_type, COUNT(*) as count").
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Group("resource_type").
		Scan(&resourceCounts).Error
	if err != nil {
		return nil, err
	}
	for _, rc := range resourceCounts {
		metrics.ByResource[rc.ResourceType] = rc.Count
	}

	// Группировка по action
	type actionCount struct {
		Action string
		Count  int64
	}
	var actionCounts []actionCount
	err = s.db.WithContext(ctx).Model(&models.AuditLog{}).
		Select("action, COUNT(*) as count").
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Group("action").
		Scan(&actionCounts).Error
	if err != nil {
		return nil, err
	}
	for _, ac := range actionCounts {
		metrics.ByAction[ac.Action] = ac.Count
	}

	return metrics, nil
}

// GetSystemMetrics возвращает агрегированные метрики системных логов за период
func (s *store) GetSystemMetrics(ctx context.Context, from, to time.Time) (*SystemMetrics, error) {
	metrics := &SystemMetrics{
		ByLevel:     make(map[string]int64),
		ByComponent: make(map[string]int64),
	}

	var total int64
	err := s.db.WithContext(ctx).Model(&models.SystemLog{}).
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Count(&total).Error
	if err != nil {
		return nil, err
	}
	metrics.Total = total

	// Группировка по level
	type levelCount struct {
		Level string
		Count int64
	}
	var levelCounts []levelCount
	err = s.db.WithContext(ctx).Model(&models.SystemLog{}).
		Select("level, COUNT(*) as count").
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Group("level").
		Scan(&levelCounts).Error
	if err != nil {
		return nil, err
	}
	for _, lc := range levelCounts {
		metrics.ByLevel[lc.Level] = lc.Count
	}

	// Группировка по component
	type componentCount struct {
		Component string
		Count     int64
	}
	var componentCounts []componentCount
	err = s.db.WithContext(ctx).Model(&models.SystemLog{}).
		Select("component, COUNT(*) as count").
		Where("timestamp >= ? AND timestamp <= ?", from, to).
		Group("component").
		Scan(&componentCounts).Error
	if err != nil {
		return nil, err
	}
	for _, cc := range componentCounts {
		metrics.ByComponent[cc.Component] = cc.Count
	}

	return metrics, nil
}

// GetAuditActivityByHour возвращает количество записей аудита по часам за последние hours часов
func (s *store) GetAuditActivityByHour(ctx context.Context, hours int) ([]TimeSeriesPoint, error) {
	var points []TimeSeriesPoint
	from := time.Now().Add(-time.Duration(hours) * time.Hour)
	query := `
		SELECT date_trunc('hour', timestamp) as timestamp, COUNT(*) as count
		FROM audit_logs
		WHERE timestamp >= ?
		GROUP BY date_trunc('hour', timestamp)
		ORDER BY timestamp
	`
	err := s.db.WithContext(ctx).Raw(query, from).Scan(&points).Error
	if err != nil {
		return nil, err
	}
	return points, nil
}

// GetTopUsers возвращает топ пользователей по количеству действий за весь период
func (s *store) GetTopUsers(ctx context.Context, limit int) ([]TopUser, error) {
	var topUsers []TopUser
	err := s.db.WithContext(ctx).Model(&models.AuditLog{}).
		Select("user_id, COUNT(*) as count").
		Where("user_id IS NOT NULL").
		Group("user_id").
		Order("count DESC").
		Limit(limit).
		Scan(&topUsers).Error
	if err != nil {
		return nil, err
	}
	return topUsers, nil
}

// Helper функции для создания логов

// NewAuditLog создает новую запись аудита с заполненными полями
func NewAuditLog(userID *uint, ip, userAgent, action, resourceType, resourceID string, details interface{}, status string) (*models.AuditLog, error) {
	var detailsJSON json.RawMessage
	if details != nil {
		b, err := json.Marshal(details)
		if err != nil {
			return nil, err
		}
		detailsJSON = b
	}
	return &models.AuditLog{
		UserID:       userID,
		IPAddress:    ip,
		UserAgent:    userAgent,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
		Status:       status,
		Timestamp:    time.Now(),
	}, nil
}

// NewSystemLog создает новую системную запись лога
func NewSystemLog(level, component, message, stackTrace string, metadata interface{}) (*models.SystemLog, error) {
	var metadataJSON json.RawMessage
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			return nil, err
		}
		metadataJSON = b
	}
	return &models.SystemLog{
		Level:      level,
		Component:  component,
		Message:    message,
		StackTrace: stackTrace,
		Metadata:   metadataJSON,
		Timestamp:  time.Now(),
	}, nil
}
