package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func StartAlertMonitor(ctx context.Context, interval time.Duration, logger *zap.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkSystemHealth(logger)
		}
	}
}

func checkSystemHealth(logger *zap.Logger) {
	// CPU usage
	cpuPercent, _ := cpu.Percent(0, false)
	if len(cpuPercent) > 0 && cpuPercent[0] > 80 {
		generateAlert("warning", "system", "High CPU usage", fmt.Sprintf("CPU at %.1f%%", cpuPercent[0]))
	}
	// Memory
	memStat, _ := mem.VirtualMemory()
	if memStat.UsedPercent > 90 {
		generateAlert("critical", "system", "High memory usage", fmt.Sprintf("Memory at %.1f%%", memStat.UsedPercent))
	}
	// Disk space for database
	// ... etc.
}

func generateAlert(severity, source, message, details string) {
	_, _ = db.DB.Exec(`INSERT INTO alerts (severity, source, message, details) VALUES (?, ?, ?, ?)`,
		severity, source, message, details)
}
