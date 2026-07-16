package device

import (
	"log"
	"os"
	"sort"
	"strings"
	"sync/atomic"
)

// LogLevel represents the severity of a SCION log message.
// Higher values are more severe. Messages below the configured level
// are silently discarded.
type LogLevel int

const (
	LogTrace LogLevel = iota
	LogDebug
	LogInfo
	LogWarn
	LogError
)

// SCIONComponent identifies a subsystem that produces SCION log messages.
type SCIONComponent string

const (
	ComponentInit            SCIONComponent = "init"
	ComponentPath            SCIONComponent = "path"
	ComponentPathEngine      SCIONComponent = "path-engine"
	ComponentPending         SCIONComponent = "pending"
	ComponentTranslateEgress SCIONComponent = "translate-egress"
	ComponentWireguardEgress SCIONComponent = "wireguard-egress"
	ComponentEgressLifecycle SCIONComponent = "egress-lifecycle"
)

// SCIONLogConfig is an immutable snapshot of SCION logging settings.
// It is stored in an atomic pointer and swapped as a unit.
type SCIONLogConfig struct {
	Level      LogLevel
	Components map[SCIONComponent]struct{}
}

// shouldComponentLog reports whether the given component is enabled.
// An empty component set means all components are enabled.
func (c *SCIONLogConfig) shouldComponentLog(comp SCIONComponent) bool {
	if len(c.Components) == 0 {
		return true
	}
	_, ok := c.Components[comp]
	return ok
}

// SCIONLogger wraps the existing WireGuard Logger with level- and
// component-aware filtering for SCION subsystems. It is safe for
// concurrent use.
//
// ERROR messages are never suppressed by component filtering and are
// always routed through the underlying Logger.Errorf.
type SCIONLogger struct {
	base  *Logger
	config atomic.Pointer[SCIONLogConfig]
}

// NewSCIONLogger creates an SCIONLogger that delegates to base.
// The initial configuration uses the default level (INFO) with all
// components enabled.
func NewSCIONLogger(base *Logger) *SCIONLogger {
	l := &SCIONLogger{base: base}
	cfg := DefaultSCIONLogConfig()
	l.config.Store(&cfg)
	return l
}

// SetConfig atomically replaces the logging configuration.
func (l *SCIONLogger) SetConfig(cfg SCIONLogConfig) {
	l.config.Store(&cfg)
}

// Config returns the current logging configuration snapshot.
func (l *SCIONLogger) Config() SCIONLogConfig {
	return *l.config.Load()
}

// shouldLog checks whether a message at the given level and component
// should be emitted. It must be called before any expensive formatting.
func (l *SCIONLogger) shouldLog(level LogLevel, comp SCIONComponent) bool {
	cfg := l.config.Load()
	if level < cfg.Level {
		return false
	}
	return cfg.shouldComponentLog(comp)
}

// Tracef logs a trace-level message if enabled.
func (l *SCIONLogger) Tracef(comp SCIONComponent, format string, args ...any) {
	if l.shouldLog(LogTrace, comp) {
		l.base.Verbosef(format, args...)
	}
}

// Debugf logs a debug-level message if enabled.
func (l *SCIONLogger) Debugf(comp SCIONComponent, format string, args ...any) {
	if l.shouldLog(LogDebug, comp) {
		l.base.Verbosef(format, args...)
	}
}

// Infof logs an info-level message if enabled.
func (l *SCIONLogger) Infof(comp SCIONComponent, format string, args ...any) {
	if l.shouldLog(LogInfo, comp) {
		l.base.Verbosef(format, args...)
	}
}

// Warnf logs a warn-level message if enabled.
func (l *SCIONLogger) Warnf(comp SCIONComponent, format string, args ...any) {
	if l.shouldLog(LogWarn, comp) {
		l.base.Verbosef(format, args...)
	}
}

// Errorf always logs through the base logger's Errorf, regardless
// of level or component filtering. ERROR messages are never hidden.
func (l *SCIONLogger) Errorf(comp SCIONComponent, format string, args ...any) {
	l.base.Errorf(format, args...)
}

// DefaultSCIONLogConfig returns the default configuration: level=INFO,
// all components enabled (empty component set).
func DefaultSCIONLogConfig() SCIONLogConfig {
	return SCIONLogConfig{
		Level:      LogInfo,
		Components: nil, // nil/empty = all components enabled
	}
}

// SCIONLogConfigFromEnv reads SCION_LOG_LEVEL and SCION_LOG_COMPONENTS
// from environment variables and returns the resulting configuration.
// Missing or empty variables fall back to defaults.
func SCIONLogConfigFromEnv() SCIONLogConfig {
	cfg := DefaultSCIONLogConfig()

	if v := os.Getenv("SCION_LOG_LEVEL"); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "trace":
			cfg.Level = LogTrace
		case "debug":
			cfg.Level = LogDebug
		case "info":
			cfg.Level = LogInfo
		case "warn", "warning":
			cfg.Level = LogWarn
		case "error":
			cfg.Level = LogError
		}
	}

	if v := os.Getenv("SCION_LOG_COMPONENTS"); v != "" {
		components := make(map[SCIONComponent]struct{})
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			components[SCIONComponent(s)] = struct{}{}
		}
		if len(components) > 0 {
			cfg.Components = components
		}
	}

	return cfg
}

// ParseSCIONLogConfig parses log level and component strings from Android config.
// Invalid level falls back to INFO. Unknown components are ignored with a warning.
// Empty component list means all components enabled.
func ParseSCIONLogConfig(levelStr, componentsStr string) SCIONLogConfig {
	cfg := DefaultSCIONLogConfig()

	// Parse level
	levelStr = strings.TrimSpace(strings.ToLower(levelStr))
	switch levelStr {
	case "trace":
		cfg.Level = LogTrace
	case "debug":
		cfg.Level = LogDebug
	case "info":
		cfg.Level = LogInfo
	case "warn", "warning":
		cfg.Level = LogWarn
	case "error":
		cfg.Level = LogError
	case "":
		// empty = default (INFO)
	default:
		log.Printf("[SCION-LOG] unknown log level %q, falling back to INFO", levelStr)
	}

	// Parse components
	if componentsStr != "" {
		components := make(map[SCIONComponent]struct{})
		validComponents := map[SCIONComponent]bool{
			ComponentInit:            true,
			ComponentPath:            true,
			ComponentPathEngine:      true,
			ComponentPending:         true,
			ComponentTranslateEgress: true,
			ComponentWireguardEgress: true,
			ComponentEgressLifecycle: true,
		}

		for _, s := range strings.Split(componentsStr, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			comp := SCIONComponent(s)
			if validComponents[comp] {
				components[comp] = struct{}{}
			} else {
				log.Printf("[SCION-LOG] unknown component ignored: %s", s)
			}
		}
		if len(components) > 0 {
			cfg.Components = components
		}
	}

	return cfg
}

// LogEffectiveConfig emits one concise log showing the active SCION logging
// configuration. Called once during initialization, at INFO level.
func LogEffectiveConfig(l *SCIONLogger, source string, debugBuild bool) {
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

	// Sort component names for deterministic output
	var compNames []string
	if len(cfg.Components) == 0 {
		compNames = []string{"all"}
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
