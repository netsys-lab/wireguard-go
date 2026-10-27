//go:build !debug

package scionlog

const IsDebugBuild = false

// In release builds, all hot-path debug/trace/info/warn methods are empty stubs.
// The Go compiler inlines these empty functions and eliminates the call sites completely (0 bytes overhead).

func (l *Logger) IsDebug() bool { return false }
func (l *Logger) IsTrace() bool { return false }

func (l *Logger) Tracef(comp Component, format string, args ...any) {}
func (l *Logger) Debugf(comp Component, format string, args ...any) {}
func (l *Logger) Infof(comp Component, format string, args ...any)  {}
func (l *Logger) Warnf(comp Component, format string, args ...any)  {}
func (l *Logger) Verbosef(format string, args ...any)                {}
func (l *Logger) Printf(format string, args ...any)                  {}

func IsDebug() bool                                     { return false }
func IsTrace() bool                                     { return false }
func Tracef(comp Component, format string, args ...any) {}
func Debugf(comp Component, format string, args ...any) {}
func Infof(comp Component, format string, args ...any)  {}
func Warnf(comp Component, format string, args ...any)  {}
func Printf(format string, args ...any)                  {}
