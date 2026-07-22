package scionlog

import (
	"sort"
	"strings"
	"sync/atomic"
)

type LogLevel int

const (
	LogTrace LogLevel = iota
	LogDebug
	LogInfo
	LogWarn
	LogError
)

type Component string

const (
	ComponentInit            Component = "init"
	ComponentPath            Component = "path"
	ComponentPathEngine      Component = "path-engine"
	ComponentPending         Component = "pending"
	ComponentTranslateEgress Component = "translate-egress"
	ComponentWireguardEgress Component = "wireguard-egress"
	ComponentEgressLifecycle Component = "egress-lifecycle"
)

type LogConfig struct {
	Level      LogLevel
	Components map[Component]struct{}
}

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

type Logger struct {
	verbosef func(string, ...any)
	errorf   func(string, ...any)
	config   atomic.Pointer[LogConfig]
}

func NewLogger(verbosef, errorf func(string, ...any)) *Logger {
	l := &Logger{verbosef: verbosef, errorf: errorf}
	cfg := DefaultConfig()
	l.config.Store(&cfg)
	return l
}

func (l *Logger) SetConfig(cfg LogConfig) {
	l.config.Store(&cfg)
}

func (l *Logger) Config() LogConfig {
	return *l.config.Load()
}

func (l *Logger) shouldLog(level LogLevel, comp Component) bool {
	cfg := l.config.Load()
	if level < cfg.Level {
		return false
	}
	return cfg.shouldComponentLog(comp)
}

func (l *Logger) Tracef(comp Component, format string, args ...any) {
	if l.shouldLog(LogTrace, comp) {
		l.verbosef(format, args...)
	}
}

func (l *Logger) Debugf(comp Component, format string, args ...any) {
	if l.shouldLog(LogDebug, comp) {
		l.verbosef(format, args...)
	}
}

func (l *Logger) Infof(comp Component, format string, args ...any) {
	if l.shouldLog(LogInfo, comp) {
		l.verbosef(format, args...)
	}
}

func (l *Logger) Warnf(comp Component, format string, args ...any) {
	if l.shouldLog(LogWarn, comp) {
		l.verbosef(format, args...)
	}
}

func (l *Logger) Errorf(comp Component, format string, args ...any) {
	l.errorf(format, args...)
}

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
