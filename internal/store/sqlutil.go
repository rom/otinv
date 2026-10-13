package store

import (
	"encoding/json"
	"reflect"
	"strings"
)

// nullString stores an empty string as NULL, so that absent values read back
// as absent rather than as the empty string in a JSON export.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullUint16(p *uint16) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func nullUint32(p *uint32) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

// marshalJSON encodes a map or slice, storing an empty one as NULL so that it
// reads back nil rather than as an empty container.
func marshalJSON(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		if rv.IsNil() || rv.Len() == 0 {
			return nil, nil
		}
	default:
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// unmarshalJSON decodes a column that may be NULL, leaving the target at its
// zero value when it is.
func unmarshalJSON(data []byte, target any) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, target)
}

func joinAnd(clauses []string) string { return strings.Join(clauses, " AND ") }
