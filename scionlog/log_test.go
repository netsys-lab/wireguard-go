package scionlog

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func captureLogger() (*Logger, *[]string, *[]string) {
	verbose := &[]string{}
	errs := &[]string{}
	l := NewLogger(
		func(format string, args ...any) {
			*verbose = append(*verbose, fmt.Sprintf(format, args...))
		},
		func(format string, args ...any) {
			*errs = append(*errs, fmt.Sprintf(format, args...))
		},
	)
	return l, verbose, errs
}

func TestLogger_TraceSuppressedAtInfo(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogInfo})
	l.Tracef(ComponentInit, "trace message")
	if len(*verbose) != 0 {
		t.Errorf("TRACE should be suppressed at INFO level, got %d messages", len(*verbose))
	}
}

func TestLogger_DebugSuppressedAtInfo(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogInfo})
	l.Debugf(ComponentPath, "debug message")
	if len(*verbose) != 0 {
		t.Errorf("DEBUG should be suppressed at INFO level, got %d messages", len(*verbose))
	}
}

func TestLogger_InfoEmittedAtInfo(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogInfo})
	l.Infof(ComponentPending, "info message %d", 42)
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 INFO message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "info message 42" {
		t.Errorf("expected %q, got %q", "info message 42", (*verbose)[0])
	}
}

func TestLogger_ErrorAlwaysEmitted(t *testing.T) {
	l, _, errs := captureLogger()
	l.SetConfig(LogConfig{Level: LogTrace})
	l.Errorf(ComponentTranslateEgress, "error %s", "boom")
	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
	if (*errs)[0] != "error boom" {
		t.Errorf("expected %q, got %q", "error boom", (*errs)[0])
	}
}

func TestLogger_ErrorEmittedEvenAtErrorLevel(t *testing.T) {
	l, _, errs := captureLogger()
	l.SetConfig(LogConfig{Level: LogError})
	l.Errorf(ComponentWireguardEgress, "always visible")
	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
}

func TestLogger_ComponentFilterSuppressesDebug(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{
		Level: LogDebug,
		Components: map[Component]struct{}{
			ComponentPath: {},
		},
	})
	l.Debugf(ComponentPath, "path msg")
	l.Debugf(ComponentPending, "pending msg")
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message (path only), got %d: %v", len(*verbose), *verbose)
	}
	if (*verbose)[0] != "path msg" {
		t.Errorf("expected %q, got %q", "path msg", (*verbose)[0])
	}
}

func TestLogger_ComponentFilterDoesNotSuppressError(t *testing.T) {
	l, _, errs := captureLogger()
	l.SetConfig(LogConfig{
		Level: LogDebug,
		Components: map[Component]struct{}{
			ComponentPath: {},
		},
	})
	l.Errorf(ComponentTranslateEgress, "error in unselected component")
	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
	if (*errs)[0] != "error in unselected component" {
		t.Errorf("unexpected error message: %q", (*errs)[0])
	}
}

func TestLogger_NilComponentEnablesAll(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{
		Level:      LogDebug,
		Components: nil,
	})
	l.Debugf(ComponentInit, "init msg")
	l.Debugf(ComponentPath, "path msg")
	l.Debugf(ComponentPending, "pending msg")
	if len(*verbose) != 3 {
		t.Errorf("expected 3 messages with nil components, got %d: %v", len(*verbose), *verbose)
	}
}

func TestLogger_EmptyComponentSuppressesAll(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{
		Level:      LogDebug,
		Components: make(map[Component]struct{}),
	})
	l.Debugf(ComponentInit, "init msg")
	l.Debugf(ComponentPath, "path msg")
	if len(*verbose) != 0 {
		t.Errorf("expected 0 messages with empty non-nil component set, got %d", len(*verbose))
	}
}

func TestLogger_ExpensiveFormatterNotExecuted(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogInfo})
	formatterCalled := false
	panickyFormat := func() string {
		formatterCalled = true
		panic("formatter should not be called when level is suppressed")
	}
	if l.shouldLog(LogDebug, ComponentPath) {
		l.Debugf(ComponentPath, "msg %s", panickyFormat())
	}
	if formatterCalled {
		t.Error("expensive formatter was executed despite DEBUG being suppressed")
	}
	if len(*verbose) != 0 {
		t.Errorf("expected no messages, got %d", len(*verbose))
	}
}

func TestLogger_ConcurrentConfigSwap(t *testing.T) {
	var mu sync.Mutex
	verbose := &[]string{}
	l := NewLogger(
		func(format string, args ...any) {
			mu.Lock()
			*verbose = append(*verbose, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
		func(format string, args ...any) {},
	)
	var wg sync.WaitGroup
	const goroutines = 100
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				l.SetConfig(LogConfig{Level: LogTrace})
			} else {
				l.SetConfig(LogConfig{Level: LogError})
			}
			l.Debugf(ComponentPath, "concurrent msg from %d", id)
		}(i)
	}
	wg.Wait()
	mu.Lock()
	n := len(*verbose)
	mu.Unlock()
	if n > goroutines {
		t.Errorf("expected at most %d messages, got %d", goroutines, n)
	}
}

func TestLogger_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Level != LogInfo {
		t.Errorf("default level: expected LogInfo (%d), got %d", LogInfo, cfg.Level)
	}
	if cfg.Components != nil {
		t.Errorf("default components should be nil (all enabled), got %v", cfg.Components)
	}
}

func TestLogger_WarnfEmitted(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogWarn})
	l.Warnf(ComponentPathEngine, "warn msg")
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 WARN message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "warn msg" {
		t.Errorf("expected %q, got %q", "warn msg", (*verbose)[0])
	}
}

func TestLogger_WarnfSuppressedAtInfo(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogInfo})
	l.Warnf(ComponentPathEngine, "should not appear")
	// WARN (level 3) is above INFO (level 2), so it should NOT be suppressed.
	if len(*verbose) != 1 {
		t.Errorf("WARN should be emitted at INFO level, got %d messages", len(*verbose))
	}
}

func TestLogger_LevelHierarchy(t *testing.T) {
	l, verbose, errs := captureLogger()
	l.SetConfig(LogConfig{Level: LogTrace})
	l.Tracef(ComponentInit, "trace")
	l.Debugf(ComponentInit, "debug")
	l.Infof(ComponentInit, "info")
	l.Warnf(ComponentInit, "warn")
	if len(*verbose) != 4 {
		t.Errorf("at Trace level: expected 4 verbose messages, got %d", len(*verbose))
	}
	*verbose = nil
	*errs = nil
	l.SetConfig(LogConfig{Level: LogError})
	l.Tracef(ComponentInit, "trace")
	l.Debugf(ComponentInit, "debug")
	l.Infof(ComponentInit, "info")
	l.Warnf(ComponentInit, "warn")
	l.Errorf(ComponentInit, "error")
	if len(*verbose) != 0 {
		t.Errorf("at Error level: expected 0 verbose messages, got %d", len(*verbose))
	}
	if len(*errs) != 1 {
		t.Errorf("at Error level: expected 1 error message, got %d", len(*errs))
	}
}

func TestLogger_ConfigSwapPreservesState(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogTrace})
	l.Debugf(ComponentPath, "before swap")
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message before swap, got %d", len(*verbose))
	}
	l.SetConfig(LogConfig{Level: LogError})
	l.Debugf(ComponentPath, "after swap")
	if len(*verbose) != 1 {
		t.Errorf("expected still 1 message after swap, got %d", len(*verbose))
	}
}

func TestConfigFromEnv(t *testing.T) {
	oldLevel := os.Getenv("SCION_LOG_LEVEL")
	oldComps := os.Getenv("SCION_LOG_COMPONENTS")
	defer func() {
		os.Setenv("SCION_LOG_LEVEL", oldLevel)
		os.Setenv("SCION_LOG_COMPONENTS", oldComps)
	}()

	os.Unsetenv("SCION_LOG_LEVEL")
	os.Unsetenv("SCION_LOG_COMPONENTS")
	cfg := ConfigFromEnv()
	if cfg.Level != LogInfo {
		t.Errorf("expected default LogInfo, got %d", cfg.Level)
	}
	if cfg.Components != nil {
		t.Errorf("expected nil components (all enabled), got %v", cfg.Components)
	}

	os.Setenv("SCION_LOG_LEVEL", "trace")
	os.Setenv("SCION_LOG_COMPONENTS", "path,pending,translate-egress")
	cfg = ConfigFromEnv()
	if cfg.Level != LogTrace {
		t.Errorf("expected LogTrace, got %d", cfg.Level)
	}
	if len(cfg.Components) != 3 {
		t.Errorf("expected 3 components, got %d", len(cfg.Components))
	}
	for _, c := range []Component{ComponentPath, ComponentPending, ComponentTranslateEgress} {
		if _, ok := cfg.Components[c]; !ok {
			t.Errorf("expected component %q to be present", c)
		}
	}
}

func TestLogger_ComponentFilterWithMultipleComponents(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{
		Level: LogDebug,
		Components: map[Component]struct{}{
			ComponentPath:           {},
			ComponentTranslateEgress: {},
		},
	})
	l.Debugf(ComponentPath, "ok")
	l.Debugf(ComponentTranslateEgress, "ok")
	l.Debugf(ComponentPending, "nope")
	l.Debugf(ComponentWireguardEgress, "nope")
	l.Debugf(ComponentInit, "nope")
	if len(*verbose) != 2 {
		t.Errorf("expected 2 messages, got %d: %v", len(*verbose), *verbose)
	}
}

func TestLogger_SuppressesInfoWhenLevelIsWarn(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogWarn})
	l.Infof(ComponentPath, "should not appear")
	if len(*verbose) != 0 {
		t.Errorf("INFO should be suppressed at WARN level, got %d messages", len(*verbose))
	}
}

func TestLogger_EmptyFormatString(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogDebug})
	l.Debugf(ComponentInit, "")
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "" {
		t.Errorf("expected empty string, got %q", (*verbose)[0])
	}
}

func TestLogger_ManyArgs(t *testing.T) {
	l, verbose, _ := captureLogger()
	l.SetConfig(LogConfig{Level: LogTrace})
	args := make([]any, 100)
	for i := range args {
		args[i] = i
	}
	format := strings.Repeat("%d ", 100)
	l.Tracef(ComponentPath, format, args...)
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message, got %d", len(*verbose))
	}
}

func TestParseConfig_TraceLevel(t *testing.T) {
	cfg := ParseConfig("trace", "")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
}

func TestParseConfig_DebugLevel(t *testing.T) {
	cfg := ParseConfig("debug", "")
	if cfg.Level != LogDebug {
		t.Errorf("level = %v, want LogDebug", cfg.Level)
	}
}

func TestParseConfig_InfoLevel(t *testing.T) {
	cfg := ParseConfig("info", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo", cfg.Level)
	}
}

func TestParseConfig_WarnLevel(t *testing.T) {
	cfg := ParseConfig("warn", "")
	if cfg.Level != LogWarn {
		t.Errorf("level = %v, want LogWarn", cfg.Level)
	}
}

func TestParseConfig_ErrorLevel(t *testing.T) {
	cfg := ParseConfig("error", "")
	if cfg.Level != LogError {
		t.Errorf("level = %v, want LogError", cfg.Level)
	}
}

func TestParseConfig_InvalidLevelFallsBackToInfo(t *testing.T) {
	cfg := ParseConfig("bogus", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo (fallback)", cfg.Level)
	}
}

func TestParseConfig_EmptyLevelDefaultsToInfo(t *testing.T) {
	cfg := ParseConfig("", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo (default)", cfg.Level)
	}
}

func TestParseConfig_Components(t *testing.T) {
	cfg := ParseConfig("trace", "path,pending,translate-egress")
	if len(cfg.Components) != 3 {
		t.Errorf("components count = %d, want 3", len(cfg.Components))
	}
	if _, ok := cfg.Components[ComponentPath]; !ok {
		t.Error("missing ComponentPath")
	}
	if _, ok := cfg.Components[ComponentPending]; !ok {
		t.Error("missing ComponentPending")
	}
	if _, ok := cfg.Components[ComponentTranslateEgress]; !ok {
		t.Error("missing ComponentTranslateEgress")
	}
}

func TestParseConfig_UnknownComponentIgnored(t *testing.T) {
	cfg := ParseConfig("trace", "path,unknown-component,pending")
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2 (unknown should be ignored)", len(cfg.Components))
	}
	if _, ok := cfg.Components["unknown-component"]; ok {
		t.Error("unknown-component should not be in components")
	}
}

func TestParseConfig_Deduplicates(t *testing.T) {
	cfg := ParseConfig("trace", "path,path,pending")
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2 (deduplicated)", len(cfg.Components))
	}
}

func TestParseConfig_EmptyComponentsNone(t *testing.T) {
	cfg := ParseConfig("trace", "")
	if len(cfg.Components) != 0 {
		t.Errorf("components count = %d, want 0 (empty = none)", len(cfg.Components))
	}
	if cfg.Components == nil {
		t.Error("empty string should produce empty non-nil map (none), got nil (all)")
	}
}

func TestParseConfig_AllComponents(t *testing.T) {
	cfg := ParseConfig("trace", "all")
	if cfg.Components != nil {
		t.Errorf("\"all\" should produce nil components, got %v", cfg.Components)
	}
}

func TestParseConfig_CaseInsensitiveLevel(t *testing.T) {
	cfg := ParseConfig("TRACE", "")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
}

func TestParseConfig_TrimsWhitespace(t *testing.T) {
	cfg := ParseConfig("  trace  ", "  path , pending  ")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2", len(cfg.Components))
	}
}
