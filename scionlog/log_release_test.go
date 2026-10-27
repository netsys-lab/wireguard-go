//go:build !debug

package scionlog

import (
	"testing"
)

func TestReleaseLogger_ZeroCost(t *testing.T) {
	if IsDebugBuild {
		t.Errorf("expected IsDebugBuild to be false in release mode")
	}
	if IsDebug() {
		t.Errorf("expected IsDebug() to return false in release mode")
	}
	if IsTrace() {
		t.Errorf("expected IsTrace() to return false in release mode")
	}

	var called bool
	l := NewLogger(func(format string, args ...any) {
		called = true
	}, func(format string, args ...any) {
		called = true
	})

	if l.IsDebug() {
		t.Errorf("expected l.IsDebug() to return false in release mode")
	}
	if l.IsTrace() {
		t.Errorf("expected l.IsTrace() to return false in release mode")
	}

	// Hot-path methods should be no-ops
	l.Tracef(ComponentFlow, "trace %s", "arg")
	l.Debugf(ComponentPath, "debug %s", "arg")
	l.Infof(ComponentInit, "info %s", "arg")
	l.Warnf(ComponentInit, "warn %s", "arg")
	l.Verbosef("verbose %s", "arg")
	l.Printf("print %s", "arg")

	if called {
		t.Errorf("expected no log calls to be emitted in release mode")
	}

	// Errorf should still work
	l.Errorf(ComponentInit, "error %s", "critical")
	if !called {
		t.Errorf("expected Errorf to still be emitted in release mode")
	}
}
