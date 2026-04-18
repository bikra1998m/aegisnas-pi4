package audit

import (
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func Log(user, action, details, result string) {
	logger := zap.L()
	logger.Info("audit",
		zap.String("user", user),
		zap.String("action", action),
		zap.String("details", details),
		zap.String("result", result),
	)

	if db.DB != nil {
		_, err := db.DB.Exec(`INSERT INTO audit_logs (timestamp, user, action, details, result) VALUES (?, ?, ?, ?, ?)`,
			time.Now(), user, action, details, result)
		if err != nil {
			logger.Error("failed to persist audit log", zap.Error(err))
		}
	}
}