package scionlog

import (
	"sort"
	"strings"
	"sync/atomic"
)

// LogLevel orders the SCION log levels from most (LogTrace) to least verbose
// (LogError). A message is emitted when its level is >= the configured level.
type LogLevel int

const (
	LogTrace LogLevel = iota
	LogDebug
	LogInfo
	LogWarn
	LogError
)

// Component tags a log message with the subsystem it belongs to. The configured
// component filter decides which components are emitted.
type Component string

const (
	ComponentInit            Component = "init"
	ComponentPath            Component = "path"
	ComponentPathEngine      Component = "path-engine"
	ComponentPending         Component = "pending"
	ComponentTranslateEgress Component = "translate-egress"
	ComponentWireguardEgress Component = "wireguard-egress"
	ComponentEgressLifecycle Component = "egress-lifecycle"
	ComponentFlow            Component = "flow"
)

// LogConfig holds the active level and component filter.
// Components == nil means all components, an empty map means none.
type LogConfig struct {
	Level      LogLevel
	Components map[Component]struct{}
}

// shouldComponentLog applies the component filter (nil = all, empty = none).
func (c *LogConfig) shouldComponentLog(comp Component) bool {
	if c.Components == nil {
		return true
	}
	if len(c.Components) == 0 {
		return false
	}
	_, ok := c.Components[comp]
	return ok
}

// Logger is a level- and component-filtered wrapper around the WireGuard
// device.Logger functions. All non-error levels are written through verbosef
// (on Android: logcat priority DEBUG), errors through errorf (priority ERROR).
// The config is stored atomically so it can be swapped at runtime.
type Logger struct {
	verbosef func(string, ...any)
	errorf   func(string, ...any)
	config   atomic.Pointer[LogConfig]
}

// NewLogger creates a Logger that writes through the given functions and starts
// with DefaultConfig. If verbosef is a discard function (wireguardCoreLogLevel
// error/silent), all trace/debug/info/warn output is discarded as well.
func NewLogger(verbosef, errorf func(string, ...any)) *Logger {
	l := &Logger{verbosef: verbosef, errorf: errorf}
	cfg := DefaultConfig()
	l.config.Store(&cfg)
	return l
}

// SetConfig atomically replaces the active logging configuration.
func (l *Logger) SetConfig(cfg LogConfig) {
	l.config.Store(&cfg)
}

// Config returns a copy of the active logging configuration.
func (l *Logger) Config() LogConfig {
	return *l.config.Load()
}

// shouldLog reports whether a message of the given level and component passes
// both the level threshold and the component filter.
func (l *Logger) shouldLog(level LogLevel, comp Component) bool {
	cfg := l.config.Load()
	if level < cfg.Level {
		return false
	}
	return cfg.shouldComponentLog(comp)
}

// Tracef logs very detailed diagnostics (per packet / per path) via verbosef.
func (l *Logger) Tracef(comp Component, format string, args ...any) {
	if l.shouldLog(LogTrace, comp) {
		l.verbosef(format, args...)
	}
}

// Debugf logs debug information via verbosef.
func (l *Logger) Debugf(comp Component, format string, args ...any) {
	if l.shouldLog(LogDebug, comp) {
		l.verbosef(format, args...)
	}
}

// Infof logs informational state changes via verbosef.
func (l *Logger) Infof(comp Component, format string, args ...any) {
	if l.shouldLog(LogInfo, comp) {
		l.verbosef(format, args...)
	}
}

// Warnf logs recoverable problems. Note: it uses verbosef, so on Android it
// appears with logcat priority DEBUG, not WARN.
func (l *Logger) Warnf(comp Component, format string, args ...any) {
	if l.shouldLog(LogWarn, comp) {
		l.verbosef(format, args...)
	}
}

// Errorf always logs via errorf. It ignores both the level threshold and the
// component filter.
func (l *Logger) Errorf(comp Component, format string, args ...any) {
	l.errorf(format, args...)
}

// LogEffectiveConfig emits one "[SCION-LOG-CONFIG]" line describing the active
// configuration (component init, level info). The dump flags in the message are
// hard-coded to false; the Android dump flags are currently not evaluated.
func LogEffectiveConfig(l *Logger, source string, debugBuild bool) {
	cfg := l.Config()

	levelStr := "info"
	switch cfg.Level {
	case LogTrace:
		levelStr = "trace"
	case LogDebug:
		levelStr = "debug"
	case LogInfo:
		levelStr = "info"
	case LogWarn:
		levelStr = "warn"
	case LogError:
		levelStr = "error"
	}

	var compNames []string
	if cfg.Components == nil {
		compNames = []string{"all"}
	} else if len(cfg.Components) == 0 {
		compNames = []string{"none"}
	} else {
		for c := range cfg.Components {
			compNames = append(compNames, string(c))
		}
		sort.Strings(compNames)
	}

	l.Infof(ComponentInit,
		"[SCION-LOG-CONFIG] source=%s level=%s components=%s fullTopology=false packetBytes=false pathBytes=false internalStructs=false debugBuild=%v",
		source, levelStr, strings.Join(compNames, ","), debugBuild)
}
