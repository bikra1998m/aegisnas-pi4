package radius

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// ValidateVoucher checks a voucher code and returns the associated role and duration.
func ValidateVoucher(code string) (role string, durationMinutes int, err error) {
	if db.DB == nil {
		return "", 0, fmt.Errorf("database not initialized")
	}

	var (
		roleDB     string
		duration   int
		usageLimit int
		usedCount  int
		expiresAt  sql.NullTime
	)

	err = db.DB.QueryRow(`SELECT role, duration_minutes, usage_limit, used_count, expires_at
		FROM vouchers WHERE code = ?`, code).Scan(&roleDB, &duration, &usageLimit, &usedCount, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", 0, fmt.Errorf("invalid voucher code")
		}
		return "", 0, err
	}

	if usedCount >= usageLimit {
		return "", 0, fmt.Errorf("voucher usage limit exceeded")
	}
	if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
		return "", 0, fmt.Errorf("voucher expired")
	}

	// Increment usage count
	_, err = db.DB.Exec("UPDATE vouchers SET used_count = used_count + 1 WHERE code = ?", code)
	if err != nil {
		return "", 0, err
	}

	return roleDB, duration, nil
}
