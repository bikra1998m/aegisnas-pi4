package db

import (
	"regexp"
	"strings"
)

var sqliteTimeModifier = regexp.MustCompile(`(?i)^'([+-])([0-9]+) (seconds?|minutes?|hours?|days?)'$`)

// Rewrite only SQL function tokens, never literals, quoted identifiers or
// comments. Nested expressions and placeholders must retain their order.
// Unsupported modifiers are left for PostgreSQL to reject, not approximated.
func rewriteSQLiteTimeFunctions(query string) string {
	var out strings.Builder
	for i := 0; i < len(query); {
		if end, ok := sqlQuotedSpan(query, i); ok {
			out.WriteString(query[i : end+1])
			i = end + 1
			continue
		}
		if isSQLWordByte(query[i]) {
			end := i + 1
			for end < len(query) && isSQLWordByte(query[end]) {
				end++
			}
			open := end
			for open < len(query) && strings.ContainsRune(" \t\r\n", rune(query[open])) {
				open++
			}
			if strings.EqualFold(query[i:end], "datetime") && open < len(query) && query[open] == '(' {
				if args, close, ok := sqlFunctionArguments(query, open); ok {
					if rewritten, ok := postgresDateTime(args); ok {
						out.WriteString(rewritten)
						i = close + 1
						continue
					}
				}
			}
			out.WriteString(query[i:end])
			i = end
			continue
		}
		out.WriteByte(query[i])
		i++
	}
	return out.String()
}

func postgresDateTime(args []string) (string, bool) {
	if len(args) == 0 || len(args) > 2 || strings.TrimSpace(args[0]) == "" {
		return "", false
	}
	value := strings.TrimSpace(args[0])
	if strings.EqualFold(value, "'now'") {
		value = "CURRENT_TIMESTAMP"
	} else {
		// Existing APIs represent absent timestamps as NULL or empty text.
		// Casting through text handles either TEXT or native TIMESTAMPTZ columns.
		value = "CAST(NULLIF(CAST(" + rewriteSQLiteTimeFunctions(value) + " AS TEXT), '') AS TIMESTAMPTZ)"
	}
	if len(args) == 2 {
		modifier := sqliteTimeModifier.FindStringSubmatch(strings.TrimSpace(args[1]))
		if modifier == nil {
			return "", false
		}
		value = "(" + value + " " + modifier[1] + " INTERVAL '" + modifier[2] + " " + modifier[3] + "')"
	}
	return value, true
}

func isSQLWordByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func sqlQuotedSpan(query string, start int) (int, bool) {
	switch query[start] {
	case '\'':
		return skipSingleQuoted(query, start), true
	case '"':
		return skipDoubleQuoted(query, start), true
	case '$':
		return skipDollarQuoted(query, start)
	case '-':
		if start+1 < len(query) && query[start+1] == '-' {
			return skipLineComment(query, start), true
		}
	case '/':
		if start+1 < len(query) && query[start+1] == '*' {
			return skipBlockComment(query, start), true
		}
	}
	return start, false
}

func sqlFunctionArguments(query string, open int) ([]string, int, bool) {
	var args []string
	start, depth := open+1, 1
	for i := start; i < len(query); i++ {
		if end, ok := sqlQuotedSpan(query, i); ok {
			i = end
			continue
		}
		switch query[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return append(args, query[start:i]), i, true
			}
		case ',':
			if depth == 1 {
				args = append(args, query[start:i])
				start = i + 1
			}
		}
	}
	return nil, open, false
}
