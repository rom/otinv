package ingest_test

import (
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/modbus"
)

// newModbus returns a dissector instance for tests that need their own
// registry rather than the process-wide one.
func newModbus(t *testing.T) dissect.Dissector {
	t.Helper()
	return modbus.New()
}
