package db

import (
	"database/sql/driver"
	"io"
	"reflect"
	"time"
)

// pgx may decode binary timestamps in the client's local zone regardless of
// PostgreSQL's TimeZone setting. The application contract uses UTC timestamps.
// Preserve the underlying column metadata and result-set behavior.
type postgresUTCRows struct{ driver.Rows }

func utcPostgreSQLRows(rows driver.Rows, err error) (driver.Rows, error) {
	if err != nil {
		return nil, err
	}
	return postgresUTCRows{rows}, nil
}

func (r postgresUTCRows) Next(values []driver.Value) error {
	if err := r.Rows.Next(values); err != nil {
		return err
	}
	for i, value := range values {
		if timestamp, ok := value.(time.Time); ok {
			values[i] = timestamp.UTC()
		}
	}
	return nil
}

func (r postgresUTCRows) ColumnTypeDatabaseTypeName(i int) string {
	if rows, ok := r.Rows.(driver.RowsColumnTypeDatabaseTypeName); ok {
		return rows.ColumnTypeDatabaseTypeName(i)
	}
	return ""
}
func (r postgresUTCRows) ColumnTypeLength(i int) (int64, bool) {
	if rows, ok := r.Rows.(driver.RowsColumnTypeLength); ok {
		return rows.ColumnTypeLength(i)
	}
	return 0, false
}
func (r postgresUTCRows) ColumnTypeNullable(i int) (bool, bool) {
	if rows, ok := r.Rows.(driver.RowsColumnTypeNullable); ok {
		return rows.ColumnTypeNullable(i)
	}
	return false, false
}
func (r postgresUTCRows) ColumnTypePrecisionScale(i int) (int64, int64, bool) {
	if rows, ok := r.Rows.(driver.RowsColumnTypePrecisionScale); ok {
		return rows.ColumnTypePrecisionScale(i)
	}
	return 0, 0, false
}
func (r postgresUTCRows) ColumnTypeScanType(i int) reflect.Type {
	if rows, ok := r.Rows.(driver.RowsColumnTypeScanType); ok {
		return rows.ColumnTypeScanType(i)
	}
	return reflect.TypeFor[any]()
}
func (r postgresUTCRows) HasNextResultSet() bool {
	if rows, ok := r.Rows.(driver.RowsNextResultSet); ok {
		return rows.HasNextResultSet()
	}
	return false
}
func (r postgresUTCRows) NextResultSet() error {
	if rows, ok := r.Rows.(driver.RowsNextResultSet); ok {
		return rows.NextResultSet()
	}
	return io.EOF
}
