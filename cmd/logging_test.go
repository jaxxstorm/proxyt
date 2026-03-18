package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBuildRuntimeLoggerDefaultsToInfoLevel(t *testing.T) {
	var output bytes.Buffer

	logger, err := buildRuntimeLogger(false, &output, "")
	if err != nil {
		t.Fatalf("build runtime logger: %v", err)
	}
	t.Cleanup(func() {
		_ = logger.Close()
	})

	logger.Debug("ignore me")
	logger.Info("hello")

	records := decodeLogRecords(t, loggedBytes(&output))
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if got := records[0]["level"]; got != "info" {
		t.Fatalf("level = %v, want info", got)
	}
}

func TestBuildRuntimeLoggerUsesDebugLevelWhenEnabled(t *testing.T) {
	var output bytes.Buffer

	logger, err := buildRuntimeLogger(true, &output, "")
	if err != nil {
		t.Fatalf("build runtime logger: %v", err)
	}
	t.Cleanup(func() {
		_ = logger.Close()
	})

	logger.Debug("hello")

	records := decodeLogRecords(t, loggedBytes(&output))
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if got := records[0]["level"]; got != "debug" {
		t.Fatalf("level = %v, want debug", got)
	}
	if got := records[0]["msg"]; got != "hello" {
		t.Fatalf("msg = %v, want hello", got)
	}
}

func TestBuildRuntimeLoggerReturnsConfigErrors(t *testing.T) {
	var output bytes.Buffer

	logger, err := buildRuntimeLogger(false, &output, "/tmp/proxyt.log")
	if err == nil {
		t.Fatal("expected conflicting output settings to fail")
	}
	if logger != nil {
		t.Fatal("expected logger to be nil on error")
	}
}

func decodeLogRecords(t *testing.T, payload []byte) []map[string]any {
	t.Helper()

	lines := bytes.Split(bytes.TrimSpace(payload), []byte("\n"))
	if len(lines) == 1 && len(lines[0]) == 0 {
		return nil
	}

	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		records = append(records, record)
	}

	return records
}
