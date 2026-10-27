//go:build debug

package scionlog

import (
	"log"
)

const IsDebugBuild = true

func (l *Logger) IsDebug() bool {
	if l == nil {
		return true
	}
	cfg := l.config.Load()
	if cfg == nil {
		return true
	}
	return cfg.Level <= LogDebug
}

func (l *Logger) IsTrace() bool {
	if l == nil {
		return true
	}
	cfg := l.config.Load()
	if cfg == nil {
		return true
	}
	return cfg.Level <= LogTrace
}

func (l *Logger) Tracef(comp Component, format string, args ...any) {
	if l != nil && l.shouldLog(LogTrace, comp) {
		if l.verbosef != nil {
			l.verbosef(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

func (l *Logger) Debugf(comp Component, format string, args ...any) {
	if l != nil && l.shouldLog(LogDebug, comp) {
		if l.verbosef != nil {
			l.verbosef(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

func (l *Logger) Infof(comp Component, format string, args ...any) {
	if l != nil && l.shouldLog(LogInfo, comp) {
		if l.verbosef != nil {
			l.verbosef(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

func (l *Logger) Warnf(comp Component, format string, args ...any) {
	if l != nil && l.shouldLog(LogWarn, comp) {
		if l.verbosef != nil {
			l.verbosef(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

func (l *Logger) Verbosef(format string, args ...any) {
	if l != nil {
		if l.verbosef != nil {
			l.verbosef(format, args...)
		} else {
			log.Printf(format, args...)
		}
	}
}

func (l *Logger) Printf(format string, args ...any) {
	if l != nil && l.verbosef != nil {
		l.verbosef(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Package-level helpers
func IsDebug() bool {
	return true
}

func IsTrace() bool {
	return true
}

func Tracef(comp Component, format string, args ...any) {
	log.Printf(format, args...)
}

func Debugf(comp Component, format string, args ...any) {
	log.Printf(format, args...)
}

func Infof(comp Component, format string, args ...any) {
	log.Printf(format, args...)
}

func Warnf(comp Component, format string, args ...any) {
	log.Printf(format, args...)
}

func Printf(format string, args ...any) {
	log.Printf(format, args...)
}
