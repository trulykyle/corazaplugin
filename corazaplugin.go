// Package corazaplugin provides a Traefik middleware that integrates Coraza WAF
// for traffic analysis with dynamic rules monitoring.
package corazaplugin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/fsnotify/fsnotify"
)

// Config holds the plugin configuration.
type Config struct {
	RulesPath     string `json:"rulesPath,omitempty"`
	DefaultStatus int    `json:"defaultStatus,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RulesPath:     "/etc/coraza/rules",
		DefaultStatus: 403,
	}
}

// CorazaPlugin represents the Traefik Coraza middleware plugin.
type CorazaPlugin struct {
	next          http.Handler
	name          string
	rulesPath     string
	defaultStatus int
	waf           coraza.WAF
	mutex         sync.RWMutex
	watcher       *fsnotify.Watcher
	ctx           context.Context
	cancel        context.CancelFunc
}

// New creates a new CorazaPlugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate configuration
	if config.RulesPath == "" {
		return nil, fmt.Errorf("rulesPath cannot be empty")
	}

	// Ensure rules directory exists
	if _, err := os.Stat(config.RulesPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("rules directory does not exist: %s", config.RulesPath)
	}

	// Set default status if not provided
	if config.DefaultStatus == 0 {
		config.DefaultStatus = 403
	}

	// Initialize WAF
	waf, err := initWAF(config.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WAF: %v", err)
	}

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	// Create context with cancellation for watcher goroutine
	watchCtx, cancel := context.WithCancel(ctx)

	plugin := &CorazaPlugin{
		next:          next,
		name:          name,
		rulesPath:     config.RulesPath,
		defaultStatus: config.DefaultStatus,
		waf:           waf,
		watcher:       watcher,
		ctx:           watchCtx,
		cancel:        cancel,
	}

	// Start watching rules directory
	if err := plugin.startWatcher(); err != nil {
		cancel()
		watcher.Close()
		return nil, fmt.Errorf("failed to start watcher: %v", err)
	}

	return plugin, nil
}

// initWAF initializes the Coraza WAF with rules from the specified directory.
func initWAF(rulesPath string) (coraza.WAF, error) {
	// Create WAF configuration
	wafConfig := coraza.NewWAFConfig()

	// Find all rule files in the directory
	ruleFiles, err := filepath.Glob(filepath.Join(rulesPath, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("failed to find rule files: %v", err)
	}

	// Read and add each rule file
	for _, ruleFile := range ruleFiles {
		ruleContent, err := os.ReadFile(ruleFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read rule file %s: %v", ruleFile, err)
		}
		wafConfig = wafConfig.WithDirectives(string(ruleContent))
	}

	// Create WAF instance
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF: %v", err)
	}

	return waf, nil
}

// startWatcher starts monitoring the rules directory for changes.
func (p *CorazaPlugin) startWatcher() error {
	// Add rules directory to watcher
	if err := p.watcher.Add(p.rulesPath); err != nil {
		return fmt.Errorf("failed to watch rules directory: %v", err)
	}

	// Start goroutine to handle file events
	go func() {
		debounceTimer := time.NewTimer(0)
		if !debounceTimer.Stop() {
			<-debounceTimer.C
		}

		var needsReload bool

		for {
			select {
			case <-p.ctx.Done():
				// Context cancelled, stop watching
				p.watcher.Close()
				return
			case event, ok := <-p.watcher.Events:
				if !ok {
					return
				}

				// Check if the event is relevant (create, write, remove, rename)
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) ||
					event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {

					// Only process .conf files
					if filepath.Ext(event.Name) == ".conf" {
						log.Printf("Rules file changed: %s, operation: %s", event.Name, event.Op.String())
						needsReload = true

						// Reset debounce timer
						if !debounceTimer.Stop() {
							select {
							case <-debounceTimer.C:
							default:
							}
						}
						debounceTimer.Reset(500 * time.Millisecond)
					}
				}
			case err, ok := <-p.watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			case <-debounceTimer.C:
				if needsReload {
					log.Println("Reloading WAF rules...")
					p.reloadRules()
					needsReload = false
				}
			}
		}
	}()

	return nil
}

// reloadRules reloads the WAF rules from the rules directory.
func (p *CorazaPlugin) reloadRules() {
	// Initialize new WAF instance
	newWAF, err := initWAF(p.rulesPath)
	if err != nil {
		log.Printf("Failed to reload WAF rules: %v", err)
		return
	}

	// Update WAF instance with write lock
	p.mutex.Lock()
	p.waf = newWAF
	p.mutex.Unlock()

	log.Println("WAF rules reloaded successfully")
}

// ServeHTTP implements the http.Handler interface.
func (p *CorazaPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Use read lock to access WAF
	p.mutex.RLock()
	waf := p.waf
	p.mutex.RUnlock()

	// Create a new transaction
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for name, vals := range req.Header {
		for _, val := range vals {
			tx.AddRequestHeader(name, val)
		}
	}

	log.Printf("processing %v\n", req)

	// Process the request
	if it := tx.ProcessRequestHeaders(); it != nil {
		log.Printf("interruption %v\n", it.Status)
		http.Error(rw, "Request blocked", it.Status)
		return
	}

	// Check for interruption
	if it := tx.Interruption(); it != nil {
		http.Error(rw, "Request blocked by WAF", it.Status)
		return
	}

	var body []byte
	if tx.IsRequestBodyAccessible() {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, "Request body error", http.StatusInternalServerError)
			return
		}
		log.Printf("body: %v\n", string(body))
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	if it, _, err := tx.WriteRequestBody(body); err != nil || it != nil {
		if it != nil {
			log.Printf("Request status %v, rule %d\n", it.Status, it.RuleID)
			rw.WriteHeader(it.Status)
		}
		return
	}

	if it, err := tx.ProcessRequestBody(); err != nil || it != nil {
		if it != nil {
			log.Printf("Request body blocked %v, %v\n", it.Status, it.RuleID)
			rw.WriteHeader(it.Status)
		}
		return
	}

	// Continue to the next handler if no interruption
	p.next.ServeHTTP(rw, req)
}

// Close cleans up resources when the plugin is no longer needed.
func (p *CorazaPlugin) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.watcher != nil {
		return p.watcher.Close()
	}
	return nil
}
