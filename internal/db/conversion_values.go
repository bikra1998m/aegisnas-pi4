package db

import (
	"fmt"
	"math"
	"time"
)

func conversionValue(value any, kind string, options ConversionOptions, report *ConversionReport) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch kind {
	case "bigint", "integer", "smallint":
		if integer, ok := value.(int64); ok {
			return integer, nil
		}
	case "boolean":
		switch v := value.(type) {
		case bool:
			return v, nil
		case int64:
			if v == 0 || v == 1 {
				return v == 1, nil
			}
		}
	case "text", "character varying", "character":
		switch v := value.(type) {
		case string:
			return v, nil
		case []byte:
			return string(v), nil
		}
	case "bytea":
		if bytes, ok := value.([]byte); ok {
			return bytes, nil
		}
	case "double precision", "real":
		var number float64
		switch v := value.(type) {
		case float64:
			number = v
		case int64:
			if int64(float64(v)) != v {
				return nil, fmt.Errorf("integer cannot be represented exactly as a floating point value")
			}
			number = float64(v)
		default:
			return nil, fmt.Errorf("unsupported numeric representation")
		}
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, fmt.Errorf("nonfinite number cannot be converted")
		}
		if kind == "real" && float64(float32(number)) != number {
			if !options.AllowPrecisionLoss || math.IsInf(float64(float32(number)), 0) {
				return nil, fmt.Errorf("REAL conversion loses precision; explicit allow-precision-loss is required")
			}
			number = float64(float32(number))
			report.RealValuesRounded++
		}
		// PostgreSQL normalizes negative zero in some text/protocol paths.
		if number == 0 {
			number = 0
		}
		return number, nil
	case "timestamp with time zone":
		var timestamp time.Time
		switch v := value.(type) {
		case time.Time:
			timestamp = v
		case string:
			for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999", "2006-01-02"} {
				parsed, err := time.Parse(layout, v)
				if err == nil {
					timestamp = parsed
					break
				}
			}
		default:
			return nil, fmt.Errorf("unsupported timestamp representation")
		}
		if timestamp.IsZero() || timestamp.Year() < 1 || timestamp.Year() > 9999 {
			return nil, fmt.Errorf("invalid or unsupported timestamp")
		}
		if timestamp.Nanosecond()%1000 != 0 {
			if !options.AllowPrecisionLoss {
				return nil, fmt.Errorf("timestamp exceeds PostgreSQL microsecond precision; explicit allow-precision-loss is required")
			}
			report.TimestampValuesTruncated++
		}
		return timestamp.UTC().Truncate(time.Microsecond), nil
	}
	return nil, fmt.Errorf("unsupported value representation for target type %s", kind)
}
