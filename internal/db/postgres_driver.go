package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/stdlib"
)

func init() {
	sql.Register(postgresDriverName, postgresRewriteDriver{delegate: stdlib.GetDefaultDriver()})
}

type postgresRewriteDriver struct {
	delegate driver.Driver
}

func (d postgresRewriteDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.delegate.Open(name)
	if err != nil {
		return nil, err
	}
	return postgresRewriteConn{Conn: conn}, nil
}

type postgresRewriteConn struct {
	driver.Conn
}

func (c postgresRewriteConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.Conn.Prepare(rewritePostgreSQLQuery(query))
	if err != nil {
		return nil, err
	}
	return postgresRewriteStmt{Stmt: stmt}, nil
}

func (c postgresRewriteConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if prepare, ok := c.Conn.(driver.ConnPrepareContext); ok {
		stmt, err := prepare.PrepareContext(ctx, rewritePostgreSQLQuery(query))
		if err != nil {
			return nil, err
		}
		return postgresRewriteStmt{Stmt: stmt}, nil
	}
	return c.Prepare(query)
}

func (c postgresRewriteConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, rewritePostgreSQLQuery(query), args)
	}
	return nil, driver.ErrSkip
}

func (c postgresRewriteConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, rewritePostgreSQLQuery(query), args)
	}
	return nil, driver.ErrSkip
}

func (c postgresRewriteConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if begin, ok := c.Conn.(driver.ConnBeginTx); ok {
		return begin.BeginTx(ctx, opts)
	}
	return c.Conn.Begin()
}

func (c postgresRewriteConn) Ping(ctx context.Context) error {
	if pinger, ok := c.Conn.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (c postgresRewriteConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c postgresRewriteConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

func (c postgresRewriteConn) CheckNamedValue(value *driver.NamedValue) error {
	if checker, ok := c.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

type postgresRewriteStmt struct {
	driver.Stmt
}

func (s postgresRewriteStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if execer, ok := s.Stmt.(driver.StmtExecContext); ok {
		return execer.ExecContext(ctx, args)
	}
	return nil, driver.ErrSkip
}

func (s postgresRewriteStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if queryer, ok := s.Stmt.(driver.StmtQueryContext); ok {
		return queryer.QueryContext(ctx, args)
	}
	return nil, driver.ErrSkip
}

func (s postgresRewriteStmt) ColumnConverter(idx int) driver.ValueConverter {
	if converter, ok := s.Stmt.(driver.ColumnConverter); ok {
		return converter.ColumnConverter(idx)
	}
	return driver.DefaultParameterConverter
}

func rewritePostgreSQLQuery(query string) string {
	query = rewriteSQLiteTimeFunctions(query)
	query = rewriteInsertOrIgnore(query)
	return rebindQuestionPlaceholders(query)
}

var sqliteRelativeNowRE = regexp.MustCompile(`(?i)datetime\(\s*'now'\s*,\s*'-([0-9]+)\s+(second|seconds|minute|minutes|hour|hours|day|days)'\s*\)`)

func rewriteSQLiteTimeFunctions(query string) string {
	query = sqliteRelativeNowRE.ReplaceAllString(query, `(CURRENT_TIMESTAMP - INTERVAL '$1 $2')`)
	replacements := []struct {
		from string
		to   string
	}{
		{"datetime('now')", "CURRENT_TIMESTAMP"},
		{"datetime( 'now' )", "CURRENT_TIMESTAMP"},
	}
	for _, replacement := range replacements {
		query = strings.ReplaceAll(query, replacement.from, replacement.to)
	}
	return query
}

func rewriteInsertOrIgnore(query string) string {
	if !strings.Contains(strings.ToLower(query), "insert or ignore") {
		return query
	}
	query = regexp.MustCompile(`(?i)\binsert\s+or\s+ignore\s+into\b`).ReplaceAllString(query, "INSERT INTO")
	statements := splitSQLStatements(query)
	for i := range statements {
		trimmed := strings.TrimSpace(statements[i].sql)
		if !strings.HasPrefix(strings.ToLower(trimmed), "insert into ") || strings.Contains(strings.ToLower(trimmed), " on conflict ") {
			continue
		}
		statements[i].sql = strings.TrimRight(statements[i].sql, " \t\r\n") + " ON CONFLICT DO NOTHING"
	}
	var out strings.Builder
	for _, statement := range statements {
		out.WriteString(statement.sql)
		out.WriteString(statement.delimiter)
	}
	return out.String()
}

type sqlStatement struct {
	sql       string
	delimiter string
}

func splitSQLStatements(query string) []sqlStatement {
	var result []sqlStatement
	start := 0
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case '\'':
			i = skipSingleQuoted(query, i)
		case '"':
			i = skipDoubleQuoted(query, i)
		case '$':
			if end, ok := skipDollarQuoted(query, i); ok {
				i = end
			}
		case '-':
			if i+1 < len(query) && query[i+1] == '-' {
				i = skipLineComment(query, i)
			}
		case '/':
			if i+1 < len(query) && query[i+1] == '*' {
				i = skipBlockComment(query, i)
			}
		case ';':
			result = append(result, sqlStatement{sql: query[start:i], delimiter: ";"})
			start = i + 1
		}
	}
	result = append(result, sqlStatement{sql: query[start:]})
	return result
}

func rebindQuestionPlaceholders(query string) string {
	var out strings.Builder
	out.Grow(len(query) + 8)
	placeholder := 1
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case '\'':
			end := skipSingleQuoted(query, i)
			out.WriteString(query[i : end+1])
			i = end
		case '"':
			end := skipDoubleQuoted(query, i)
			out.WriteString(query[i : end+1])
			i = end
		case '$':
			if end, ok := skipDollarQuoted(query, i); ok {
				out.WriteString(query[i : end+1])
				i = end
				continue
			}
			out.WriteByte(query[i])
		case '-':
			if i+1 < len(query) && query[i+1] == '-' {
				end := skipLineComment(query, i)
				out.WriteString(query[i : end+1])
				i = end
				continue
			}
			out.WriteByte(query[i])
		case '/':
			if i+1 < len(query) && query[i+1] == '*' {
				end := skipBlockComment(query, i)
				out.WriteString(query[i : end+1])
				i = end
				continue
			}
			out.WriteByte(query[i])
		case '?':
			out.WriteString(fmt.Sprintf("$%d", placeholder))
			placeholder++
		default:
			out.WriteByte(query[i])
		}
	}
	return out.String()
}

func skipSingleQuoted(query string, start int) int {
	for i := start + 1; i < len(query); i++ {
		if query[i] == '\'' {
			if i+1 < len(query) && query[i+1] == '\'' {
				i++
				continue
			}
			return i
		}
	}
	return len(query) - 1
}

func skipDoubleQuoted(query string, start int) int {
	for i := start + 1; i < len(query); i++ {
		if query[i] == '"' {
			if i+1 < len(query) && query[i+1] == '"' {
				i++
				continue
			}
			return i
		}
	}
	return len(query) - 1
}

func skipDollarQuoted(query string, start int) (int, bool) {
	endTag := start + 1
	for endTag < len(query) && (query[endTag] == '_' || query[endTag] >= 'a' && query[endTag] <= 'z' || query[endTag] >= 'A' && query[endTag] <= 'Z' || query[endTag] >= '0' && query[endTag] <= '9') {
		endTag++
	}
	if endTag >= len(query) || query[endTag] != '$' {
		return start, false
	}
	tag := query[start : endTag+1]
	end := strings.Index(query[endTag+1:], tag)
	if end < 0 {
		return len(query) - 1, true
	}
	return endTag + 1 + end + len(tag) - 1, true
}

func skipLineComment(query string, start int) int {
	for i := start + 2; i < len(query); i++ {
		if query[i] == '\n' {
			return i
		}
	}
	return len(query) - 1
}

func skipBlockComment(query string, start int) int {
	for i := start + 2; i+1 < len(query); i++ {
		if query[i] == '*' && query[i+1] == '/' {
			return i + 1
		}
	}
	return len(query) - 1
}

var _ io.Closer = postgresRewriteConn{}
