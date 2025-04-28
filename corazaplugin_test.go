package corazaplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCorazaPlugin(t *testing.T) {
	// Create temporary rules directory
	tempDir, err := os.MkdirTemp("", "coraza-rules")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test rule file
	ruleContent := `
	SecRuleEngine On
	SecRule REQUEST_URI "@rx /blocked" "id:1000,phase:1,deny,status:403"
	`
	if err := os.WriteFile(filepath.Join(tempDir, "test.conf"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("Failed to write test rule: %v", err)
	}

	// Create plugin config
	cfg := &Config{
		RulesPath:     tempDir,
		DefaultStatus: 403,
	}

	// Create a test handler
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("OK"))
		if err != nil {
			t.Fatalf("Failed to write header %v\n", err)
		}
	})

	// Create plugin
	ctx := context.Background()
	plugin, err := New(ctx, nextHandler, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer plugin.(*CorazaPlugin).Close()

	// Test allowed request
	req1 := httptest.NewRequest("GET", "http://example.com/allowed", nil)
	w1 := httptest.NewRecorder()
	plugin.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w1.Code)
	}

	// Test blocked request
	req2 := httptest.NewRequest("GET", "http://example.com/blocked", nil)
	w2 := httptest.NewRecorder()
	plugin.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, w2.Code)
	}

	// Test dynamic rule update
	newRuleContent := `
	SecRuleEngine On
	SecRule REQUEST_URI "@rx /blocked" "id:1000,phase:1,deny,status:403"
	SecRule REQUEST_URI "@rx /newblocked" "id:1001,phase:1,deny,status:403"
	`
	if err := os.WriteFile(filepath.Join(tempDir, "test.conf"), []byte(newRuleContent), 0644); err != nil {
		t.Fatalf("Failed to update test rule: %v", err)
	}

	// Wait for rule reload
	time.Sleep(1 * time.Second)

	// Test newly blocked request
	req3 := httptest.NewRequest("GET", "http://example.com/newblocked", nil)
	w3 := httptest.NewRecorder()
	plugin.ServeHTTP(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d after rule update, got %d", http.StatusForbidden, w3.Code)
	}
}
