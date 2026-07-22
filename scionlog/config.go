package scionlog

import (
	"log"
	"os"
	"strings"
)

func DefaultConfig() LogConfig {
	return LogConfig{
		Level:      LogInfo,
		Components: nil,
	}
}

func ConfigFromEnv() LogConfig {
	cfg := DefaultConfig()

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
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "none":
			cfg.Components = make(map[Component]struct{})
		case "all":
			cfg.Components = nil
		default:
			components := make(map[Component]struct{})
			for _, s := range strings.Split(v, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				components[Component(s)] = struct{}{}
			}
			if len(components) > 0 {
				cfg.Components = components
			}
		}
	}

	return cfg
}

func ParseConfig(levelStr, componentsStr string) LogConfig {
	cfg := DefaultConfig()

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
	default:
		log.Printf("[SCION-LOG] unknown log level %q, falling back to INFO", levelStr)
	}

	componentsStr = strings.TrimSpace(strings.ToLower(componentsStr))
	switch componentsStr {
	case "", "none":
		cfg.Components = make(map[Component]struct{})
	case "all":
		cfg.Components = nil
	default:
		components := make(map[Component]struct{})
		validComponents := map[Component]bool{
			ComponentInit:            true,
			ComponentPath:            true,
			ComponentPathEngine:      true,
			ComponentPending:         true,
			ComponentTranslateEgress: true,
			ComponentWireguardEgress: true,
			ComponentEgressLifecycle: true,
			ComponentFlow:            true,
		}

		for _, s := range strings.Split(componentsStr, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			comp := Component(s)
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
