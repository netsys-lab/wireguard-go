package device

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// captureLogger creates a Logger whose Verbosef and Errorf append to
// the returned slices. This avoids writing to stdout during tests.
func captureLogger() (*Logger, *[]string, *[]string) {
	verbose := &[]string{}
	errs := &[]string{}
	l := &Logger{}
	l.Verbosef = func(format string, args ...any) {
		*verbose = append(*verbose, fmt.Sprintf(format, args...))
	}
	l.Errorf = func(format string, args ...any) {
		*errs = append(*errs, fmt.Sprintf(format, args...))
	}
	return l, verbose, errs
}

func TestSCIONLogger_TraceSuppressedAtInfo(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogInfo})

	l.Tracef(ComponentInit, "trace message")

	if len(*verbose) != 0 {
		t.Errorf("TRACE should be suppressed at INFO level, got %d messages", len(*verbose))
	}
}

func TestSCIONLogger_DebugSuppressedAtInfo(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogInfo})

	l.Debugf(ComponentPath, "debug message")

	if len(*verbose) != 0 {
		t.Errorf("DEBUG should be suppressed at INFO level, got %d messages", len(*verbose))
	}
}

func TestSCIONLogger_InfoEmittedAtInfo(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogInfo})

	l.Infof(ComponentPending, "info message %d", 42)

	if len(*verbose) != 1 {
		t.Fatalf("expected 1 INFO message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "info message 42" {
		t.Errorf("expected %q, got %q", "info message 42", (*verbose)[0])
	}
}

func TestSCIONLogger_ErrorAlwaysEmitted(t *testing.T) {
	base, _, errs := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogTrace})

	l.Errorf(ComponentTranslateEgress, "error %s", "boom")

	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
	if (*errs)[0] != "error boom" {
		t.Errorf("expected %q, got %q", "error boom", (*errs)[0])
	}
}

func TestSCIONLogger_ErrorEmittedEvenAtErrorLevel(t *testing.T) {
	base, _, errs := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogError})

	l.Errorf(ComponentWireguardEgress, "always visible")

	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
}

func TestSCIONLogger_ComponentFilterSuppressesDebug(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{
		Level:      LogDebug,
		Components: map[SCIONComponent]struct{}{
			ComponentPath: {},
		},
	})

	// Component "path" is selected — should emit.
	l.Debugf(ComponentPath, "path msg")
	// Component "pending" is NOT selected — should be suppressed.
	l.Debugf(ComponentPending, "pending msg")

	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message (path only), got %d: %v", len(*verbose), *verbose)
	}
	if (*verbose)[0] != "path msg" {
		t.Errorf("expected %q, got %q", "path msg", (*verbose)[0])
	}
}

func TestSCIONLogger_ComponentFilterDoesNotSuppressError(t *testing.T) {
	base, _, errs := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{
		Level:      LogDebug,
		Components: map[SCIONComponent]struct{}{
			ComponentPath: {},
		},
	})

	// ERROR to a non-selected component should still be emitted.
	l.Errorf(ComponentTranslateEgress, "error in unselected component")

	if len(*errs) != 1 {
		t.Fatalf("expected 1 ERROR message, got %d", len(*errs))
	}
	if (*errs)[0] != "error in unselected component" {
		t.Errorf("unexpected error message: %q", (*errs)[0])
	}
}

func TestSCIONLogger_EmptyComponentSetEnablesAll(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{
		Level:      LogDebug,
		Components: nil, // empty = all enabled
	})

	l.Debugf(ComponentInit, "init msg")
	l.Debugf(ComponentPath, "path msg")
	l.Debugf(ComponentPending, "pending msg")

	if len(*verbose) != 3 {
		t.Errorf("expected 3 messages with empty component set, got %d: %v", len(*verbose), *verbose)
	}
}

func TestSCIONLogger_ExpensiveFormatterNotExecuted(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogInfo}) // DEBUG below threshold

	// Track whether the format function is called.
	formatterCalled := false
	panickyFormat := func() string {
		formatterCalled = true
		panic("formatter should not be called when level is suppressed")
	}

	// Wrap in a conditional as callers must do for expensive formatting.
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

func TestSCIONLogger_ConcurrentConfigSwap(t *testing.T) {
	// Use mutex-protected captures for the concurrent test.
	var mu sync.Mutex
	verbose := &[]string{}

	base := &Logger{}
	base.Verbosef = func(format string, args ...any) {
		mu.Lock()
		*verbose = append(*verbose, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	base.Errorf = func(format string, args ...any) {}

	l := NewSCIONLogger(base)

	var wg sync.WaitGroup
	const goroutines = 100

	// Writer goroutines: swap config and emit messages concurrently.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			// Alternate between enabling and disabling all components.
			if id%2 == 0 {
				l.SetConfig(SCIONLogConfig{Level: LogTrace})
			} else {
				l.SetConfig(SCIONLogConfig{Level: LogError})
			}
			l.Debugf(ComponentPath, "concurrent msg from %d", id)
		}(i)
	}
	wg.Wait()

	// No race: the test is run with -race. Just verify we didn't crash
	// and that the total message count is bounded.
	mu.Lock()
	n := len(*verbose)
	mu.Unlock()
	if n > goroutines {
		t.Errorf("expected at most %d messages, got %d", goroutines, n)
	}
}

func TestSCIONLogger_DefaultConfig(t *testing.T) {
	cfg := DefaultSCIONLogConfig()
	if cfg.Level != LogInfo {
		t.Errorf("default level: expected LogInfo (%d), got %d", LogInfo, cfg.Level)
	}
	if len(cfg.Components) != 0 {
		t.Errorf("default components should be empty (all enabled), got %v", cfg.Components)
	}
}

func TestSCIONLogger_WarnfEmitted(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogWarn})

	l.Warnf(ComponentPathEngine, "warn msg")

	if len(*verbose) != 1 {
		t.Fatalf("expected 1 WARN message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "warn msg" {
		t.Errorf("expected %q, got %q", "warn msg", (*verbose)[0])
	}
}

func TestSCIONLogger_WarnfSuppressedAtInfo(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogInfo})

	l.Warnf(ComponentPathEngine, "should not appear")

	// WARN (level 3) is above INFO (level 2), so it should NOT be suppressed.
	if len(*verbose) != 1 {
		t.Errorf("WARN should be emitted at INFO level, got %d messages", len(*verbose))
	}
}

func TestSCIONLogger_LevelHierarchy(t *testing.T) {
	base, verbose, errs := captureLogger()
	l := NewSCIONLogger(base)

	// At Trace level, everything should be emitted.
	l.SetConfig(SCIONLogConfig{Level: LogTrace})
	l.Tracef(ComponentInit, "trace")
	l.Debugf(ComponentInit, "debug")
	l.Infof(ComponentInit, "info")
	l.Warnf(ComponentInit, "warn")

	if len(*verbose) != 4 {
		t.Errorf("at Trace level: expected 4 verbose messages, got %d", len(*verbose))
	}

	// At Error level, only Error should be emitted.
	*verbose = nil
	*errs = nil
	l.SetConfig(SCIONLogConfig{Level: LogError})
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

func TestSCIONLogger_ConfigSwapPreservesState(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)

	// Start with Trace enabled.
	l.SetConfig(SCIONLogConfig{Level: LogTrace})
	l.Debugf(ComponentPath, "before swap")
	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message before swap, got %d", len(*verbose))
	}

	// Swap to Error only.
	l.SetConfig(SCIONLogConfig{Level: LogError})
	l.Debugf(ComponentPath, "after swap")
	if len(*verbose) != 1 {
		t.Errorf("expected still 1 message after swap, got %d", len(*verbose))
	}
}

func TestSCIONLogConfigFromEnv(t *testing.T) {
	// Save and restore env.
	oldLevel := os.Getenv("SCION_LOG_LEVEL")
	oldComps := os.Getenv("SCION_LOG_COMPONENTS")
	defer func() {
		os.Setenv("SCION_LOG_LEVEL", oldLevel)
		os.Setenv("SCION_LOG_COMPONENTS", oldComps)
	}()

	// Empty env = defaults.
	os.Unsetenv("SCION_LOG_LEVEL")
	os.Unsetenv("SCION_LOG_COMPONENTS")
	cfg := SCIONLogConfigFromEnv()
	if cfg.Level != LogInfo {
		t.Errorf("expected default LogInfo, got %d", cfg.Level)
	}
	if len(cfg.Components) != 0 {
		t.Errorf("expected empty components, got %v", cfg.Components)
	}

	// Set level and components.
	os.Setenv("SCION_LOG_LEVEL", "trace")
	os.Setenv("SCION_LOG_COMPONENTS", "path,pending,translate-egress")
	cfg = SCIONLogConfigFromEnv()
	if cfg.Level != LogTrace {
		t.Errorf("expected LogTrace, got %d", cfg.Level)
	}
	if len(cfg.Components) != 3 {
		t.Errorf("expected 3 components, got %d", len(cfg.Components))
	}
	for _, c := range []SCIONComponent{ComponentPath, ComponentPending, ComponentTranslateEgress} {
		if _, ok := cfg.Components[c]; !ok {
			t.Errorf("expected component %q to be present", c)
		}
	}
}

func TestSCIONLogger_ComponentFilterWithMultipleComponents(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{
		Level: LogDebug,
		Components: map[SCIONComponent]struct{}{
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

func TestSCIONLogger_SuppressesInfoWhenLevelIsWarn(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogWarn})

	l.Infof(ComponentPath, "should not appear")

	if len(*verbose) != 0 {
		t.Errorf("INFO should be suppressed at WARN level, got %d messages", len(*verbose))
	}
}

func TestSCIONLogger_EmptyFormatString(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogDebug})

	l.Debugf(ComponentInit, "")

	if len(*verbose) != 1 {
		t.Fatalf("expected 1 message, got %d", len(*verbose))
	}
	if (*verbose)[0] != "" {
		t.Errorf("expected empty string, got %q", (*verbose)[0])
	}
}

func TestSCIONLogger_ManyArgs(t *testing.T) {
	base, verbose, _ := captureLogger()
	l := NewSCIONLogger(base)
	l.SetConfig(SCIONLogConfig{Level: LogTrace})

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

// --- ParseSCIONLogConfig tests ---

func TestParseSCIONLogConfig_TraceLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("trace", "")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
}

func TestParseSCIONLogConfig_DebugLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("debug", "")
	if cfg.Level != LogDebug {
		t.Errorf("level = %v, want LogDebug", cfg.Level)
	}
}

func TestParseSCIONLogConfig_InfoLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("info", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo", cfg.Level)
	}
}

func TestParseSCIONLogConfig_WarnLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("warn", "")
	if cfg.Level != LogWarn {
		t.Errorf("level = %v, want LogWarn", cfg.Level)
	}
}

func TestParseSCIONLogConfig_ErrorLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("error", "")
	if cfg.Level != LogError {
		t.Errorf("level = %v, want LogError", cfg.Level)
	}
}

func TestParseSCIONLogConfig_InvalidLevelFallsBackToInfo(t *testing.T) {
	cfg := ParseSCIONLogConfig("bogus", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo (fallback)", cfg.Level)
	}
}

func TestParseSCIONLogConfig_EmptyLevelDefaultsToInfo(t *testing.T) {
	cfg := ParseSCIONLogConfig("", "")
	if cfg.Level != LogInfo {
		t.Errorf("level = %v, want LogInfo (default)", cfg.Level)
	}
}

func TestParseSCIONLogConfig_Components(t *testing.T) {
	cfg := ParseSCIONLogConfig("trace", "path,pending,translate-egress")
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

func TestParseSCIONLogConfig_UnknownComponentIgnored(t *testing.T) {
	cfg := ParseSCIONLogConfig("trace", "path,unknown-component,pending")
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2 (unknown should be ignored)", len(cfg.Components))
	}
	if _, ok := cfg.Components["unknown-component"]; ok {
		t.Error("unknown-component should not be in components")
	}
}

func TestParseSCIONLogConfig_Deduplicates(t *testing.T) {
	cfg := ParseSCIONLogConfig("trace", "path,path,pending")
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2 (deduplicated)", len(cfg.Components))
	}
}

func TestParseSCIONLogConfig_EmptyComponentsEnablesAll(t *testing.T) {
	cfg := ParseSCIONLogConfig("trace", "")
	if len(cfg.Components) != 0 {
		t.Errorf("components count = %d, want 0 (empty = all enabled)", len(cfg.Components))
	}
}

func TestParseSCIONLogConfig_CaseInsensitiveLevel(t *testing.T) {
	cfg := ParseSCIONLogConfig("TRACE", "")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
}

func TestParseSCIONLogConfig_TrimsWhitespace(t *testing.T) {
	cfg := ParseSCIONLogConfig("  trace  ", "  path , pending  ")
	if cfg.Level != LogTrace {
		t.Errorf("level = %v, want LogTrace", cfg.Level)
	}
	if len(cfg.Components) != 2 {
		t.Errorf("components count = %d, want 2", len(cfg.Components))
	}
}
