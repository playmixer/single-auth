package audit

import (
	"context"
	"net/http"

	"github.com/playmixer/single-auth/internal/adapters/storage/audit"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/pkg/logger"
	"go.uber.org/zap"
)

// Manager управляет аудитом и системными логами
type Manager struct {
	store  audit.Store
	logger *logger.Logger
}

// New создает новый менеджер аудита
func New(store audit.Store, logger *logger.Logger) *Manager {
	return &Manager{
		store:  store,
		logger: logger,
	}
}

// LogAuthEvent логирует событие аутентификации
func (m *Manager) LogAuthEvent(ctx context.Context, userID *uint, ip, userAgent, action string, details interface{}, status string) error {
	al, err := audit.NewAuditLog(userID, ip, userAgent, action, "auth", "", details, status)
	if err != nil {
		return err
	}
	return m.store.CreateAuditLog(ctx, al)
}

// LogUserEvent логирует событие связанное с пользователем (создание, изменение, удаление)
func (m *Manager) LogUserEvent(ctx context.Context, actorID *uint, ip, userAgent, action string, resourceID uint, details interface{}, status string) error {
	al, err := audit.NewAuditLog(actorID, ip, userAgent, action, "user", string(rune(resourceID)), details, status)
	if err != nil {
		return err
	}
	return m.store.CreateAuditLog(ctx, al)
}

// LogApplicationEvent логирует событие связанное с приложением
func (m *Manager) LogApplicationEvent(ctx context.Context, actorID *uint, ip, userAgent, action string, resourceID string, details interface{}, status string) error {
	al, err := audit.NewAuditLog(actorID, ip, userAgent, action, "application", resourceID, details, status)
	if err != nil {
		return err
	}
	return m.store.CreateAuditLog(ctx, al)
}

// LogRoleEvent логирует событие связанное с ролью
func (m *Manager) LogRoleEvent(ctx context.Context, actorID *uint, ip, userAgent, action string, resourceID uint, details interface{}, status string) error {
	al, err := audit.NewAuditLog(actorID, ip, userAgent, action, "role", string(rune(resourceID)), details, status)
	if err != nil {
		return err
	}
	return m.store.CreateAuditLog(ctx, al)
}

// LogSystemError логирует системную ошибку
func (m *Manager) LogSystemError(ctx context.Context, component, message, stackTrace string, metadata interface{}) error {
	sl, err := audit.NewSystemLog("error", component, message, stackTrace, metadata)
	if err != nil {
		return err
	}
	err = m.store.CreateSystemLog(ctx, sl)
	if err != nil {
		m.logger.Error("failed to write system log", zap.Error(err))
	}
	return err
}

// LogSystemWarn логирует системное предупреждение
func (m *Manager) LogSystemWarn(ctx context.Context, component, message string, metadata interface{}) error {
	sl, err := audit.NewSystemLog("warn", component, message, "", metadata)
	if err != nil {
		return err
	}
	return m.store.CreateSystemLog(ctx, sl)
}

// LogSystemInfo логирует системную информацию
func (m *Manager) LogSystemInfo(ctx context.Context, component, message string, metadata interface{}) error {
	sl, err := audit.NewSystemLog("info", component, message, "", metadata)
	if err != nil {
		return err
	}
	return m.store.CreateSystemLog(ctx, sl)
}

// GetAuditLogs возвращает записи аудита по фильтру
func (m *Manager) GetAuditLogs(ctx context.Context, filter audit.AuditFilter) ([]models.AuditLog, error) {
	return m.store.FindAuditLogs(ctx, filter)
}

// GetSystemLogs возвращает системные логи по фильтру
func (m *Manager) GetSystemLogs(ctx context.Context, filter audit.SystemFilter) ([]models.SystemLog, error) {
	return m.store.FindSystemLogs(ctx, filter)
}

// Middleware helpers

// ExtractIP извлекает IP адрес из запроса
func ExtractIP(r *http.Request) string {
	// Пробуем заголовки прокси
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// ExtractUserAgent извлекает User-Agent
func ExtractUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// AuditContextKey ключ для хранения аудит менеджера в контексте
type AuditContextKey struct{}

// WithAuditManager добавляет менеджер аудита в контекст
func WithAuditManager(ctx context.Context, manager *Manager) context.Context {
	return context.WithValue(ctx, AuditContextKey{}, manager)
}

// FromContext извлекает менеджер аудита из контекста
func FromContext(ctx context.Context) *Manager {
	if m, ok := ctx.Value(AuditContextKey{}).(*Manager); ok {
		return m
	}
	return nil
}
