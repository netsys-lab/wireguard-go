package device

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bootstrap "golang.zx2c4.com/wireguard/translator/bootstrap"
)

type SCIONInitRetryOptions struct {
	// MaxAttempts <= 0 means retry forever.
	MaxAttempts      int
	RetryDelay       time.Duration
	BootstrapTimeout time.Duration
}

func DefaultSCIONInitRetryOptions() SCIONInitRetryOptions {
	return SCIONInitRetryOptions{
		MaxAttempts:      3,
		RetryDelay:       3 * time.Second,
		BootstrapTimeout: 10 * time.Second,
	}
}

func InfiniteSCIONInitRetryOptions() SCIONInitRetryOptions {
	return SCIONInitRetryOptions{
		MaxAttempts:      0,
		RetryDelay:       3 * time.Second,
		BootstrapTimeout: 10 * time.Second,
	}
}

func (device *Device) InitSCIONWithBootstrapRetry(
	ctx context.Context,
	scionConfig ScionDeviceConfig,
	bootstrapURL string,
	options SCIONInitRetryOptions,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if options.RetryDelay <= 0 {
		options.RetryDelay = 3 * time.Second
	}

	if options.BootstrapTimeout <= 0 {
		options.BootstrapTimeout = 10 * time.Second
	}

	if !scionConfig.Enabled {
		device.log.Verbosef("SCION retry init skipped: SCION disabled")
		return nil
	}

	if scionConfig.ConfigDir == "" {
		scionConfig.ConfigDir = filepath.Join(os.TempDir(), "wg-scion")
	}

	var lastErr error

	for attempt := 1; ; attempt++ {
		if options.MaxAttempts > 0 && attempt > options.MaxAttempts {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("SCION init cancelled: %w", ctx.Err())
		case <-device.Wait():
			return fmt.Errorf("SCION init stopped: device closed")
		default:
		}

		device.log.Verbosef("SCION bootstrap/init attempt %d started", attempt)

		if bootstrapURL != "" {
			bootstrapCtx, cancel := context.WithTimeout(ctx, options.BootstrapTimeout)
			err := bootstrap.BootstrapFetch(bootstrapCtx, bootstrapURL, scionConfig.ConfigDir)
			cancel()

			if err != nil {
				lastErr = fmt.Errorf("SCION bootstrap attempt %d failed: %w", attempt, err)
				device.log.Verbosef("%v", lastErr)
			} else {
				device.log.Verbosef("SCION bootstrap attempt %d succeeded", attempt)

				if err := device.InitSCION(scionConfig); err != nil {
					lastErr = fmt.Errorf("SCION init attempt %d failed: %w", attempt, err)
					device.log.Errorf("%v", lastErr)
				} else {
					device.log.Verbosef("SCION initialized after %d attempt(s)", attempt)
					return nil
				}
			}
		} else {
			device.log.Verbosef("No SCION bootstrap URL provided, trying InitSCION from config dir: %s", scionConfig.ConfigDir)

			if err := device.InitSCION(scionConfig); err != nil {
				lastErr = fmt.Errorf("SCION init attempt %d failed: %w", attempt, err)
				device.log.Errorf("%v", lastErr)
			} else {
				device.log.Verbosef("SCION initialized after %d attempt(s)", attempt)
				return nil
			}
		}

		if options.MaxAttempts > 0 && attempt >= options.MaxAttempts {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("SCION init cancelled during retry delay: %w", ctx.Err())
		case <-device.Wait():
			return fmt.Errorf("SCION init stopped during retry delay: device closed")
		case <-time.After(options.RetryDelay):
		}
	}

	if lastErr == nil {
		return fmt.Errorf("SCION init failed after %d attempts", options.MaxAttempts)
	}

	return fmt.Errorf("SCION init failed after %d attempts: %w", options.MaxAttempts, lastErr)
}
