package models

import (
	"encoding/json"
	"time"
)

// AuditLog представляет запись аудита пользовательских действий
type AuditLog struct {
	ID           uint            `gorm:"primarykey" json:"id"`
	Timestamp    time.Time       `gorm:"index:idx_audit_timestamp" json:"timestamp"`
	UserID       *uint           `gorm:"index:idx_audit_user" json:"user_id"` // nullable для системных событий
	IPAddress    string          `gorm:"size:45" json:"ip_address"`           // IPv6 max length
	UserAgent    string          `gorm:"type:text" json:"user_agent"`
	Action       string          `gorm:"size:100;index:idx_audit_action" json:"action"`
	ResourceType string          `gorm:"size:50" json:"resource_type"`   // "user", "application", "role", "auth"
	ResourceID   string          `gorm:"size:100" json:"resource_id"`    // ID ресурса (может быть UUID или число)
	Details      json.RawMessage `gorm:"type:jsonb" json:"details"`      // Детализированные данные в JSON
	Status       string          `gorm:"size:20" json:"status"`          // "success", "failure"
	ErrorMessage string          `gorm:"type:text" json:"error_message"` // если Status = "failure"
	CreatedAt    time.Time       `json:"created_at"`
}

// SystemLog представляет системные логи (ошибки, предупреждения, информация)
type SystemLog struct {
	ID         uint            `gorm:"primarykey" json:"id"`
	Timestamp  time.Time       `gorm:"index:idx_system_timestamp" json:"timestamp"`
	Level      string          `gorm:"size:10;index:idx_system_level" json:"level"`         // "info", "warn", "error", "debug"
	Component  string          `gorm:"size:50;index:idx_system_component" json:"component"` // "auth", "storage", "api", "admin"
	Message    string          `gorm:"type:text" json:"message"`
	StackTrace string          `gorm:"type:text" json:"stack_trace"` // для ошибок
	Metadata   json.RawMessage `gorm:"type:jsonb" json:"metadata"`   // дополнительные контекстные данные
	CreatedAt  time.Time       `json:"created_at"`
}

// JSONB совместимость
func (a AuditLog) MarshalBinary() ([]byte, error) {
	return json.Marshal(a)
}

func (a *AuditLog) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, a)
}

func (s SystemLog) MarshalBinary() ([]byte, error) {
	return json.Marshal(s)
}

func (s *SystemLog) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, s)
}
