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
