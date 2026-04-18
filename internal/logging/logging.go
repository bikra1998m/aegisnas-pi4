package logging

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger *zap.Logger

func Init(level string, output string) error {
	var writer zapcore.WriteSyncer
	if output == "stdout" {
		writer = zapcore.AddSync(os.Stdout)
	} else {
		// Use lumberjack for rotation
		lj := &lumberjack.Logger{
			Filename:   output,
			MaxSize:    10, // megabytes
			MaxBackups: 5,
			MaxAge:     30, // days
			Compress:   true,
		}
		writer = zapcore.AddSync(lj)
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), writer, zapLevel)
	logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return nil
}

func L() *zap.Logger {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return logger
}

func Sync() {
	if logger != nil {
		_ = logger.Sync()
	}
}
