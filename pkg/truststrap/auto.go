// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	// DefaultPerMethodTimeout is the default timeout applied to each
	// individual bootstrap method attempt.
	DefaultPerMethodTimeout = 15 * time.Second
)

// AutoConfig configures the AutoBootstrapper which tries multiple
// bootstrap methods in priority order.
type AutoConfig struct {
	// MethodOrder defines the priority order in which bootstrap methods
	// are attempted. Default: DefaultMethodOrder.
	MethodOrder []Method

	// PerMethodTimeout is the timeout applied to each individual method
	// attempt. Default: 15s.
	PerMethodTimeout time.Duration

	// DANE configures the DANE/TLSA bootstrapper. Nil means skip DANE.
	DANE *DANEConfig

	// Noise configures the Noise_NK bootstrapper. Nil means skip Noise.
	Noise *NoiseConfig

	// SPKI configures the SPKI-pinned TLS bootstrapper. Nil means skip SPKI.
	SPKI *SPKIConfig

	// Direct configures the direct HTTPS bootstrapper. Nil means skip Direct.
	Direct *DirectConfig

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// methodFactory creates a Bootstrapper instance. The bootstrapper is created
// fresh for each attempt and closed after the attempt completes.
type methodFactory func() (Bootstrapper, error)

// AutoBootstrapper implements Bootstrapper by trying multiple bootstrap
// methods in priority order. It creates a fresh bootstrapper for each
// attempt and returns the first successful result.
type AutoBootstrapper struct {
	factories  map[Method]methodFactory
	order      []Method
	perTimeout time.Duration
	logger     *slog.Logger
}

// NewAutoBootstrapper creates a new AutoBootstrapper from the given config.
// It builds a factory map from non-nil method configs and validates that
// at least one method is configured in the order.
func NewAutoBootstrapper(cfg *AutoConfig) (*AutoBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	perTimeout := cfg.PerMethodTimeout
	if perTimeout == 0 {
		perTimeout = DefaultPerMethodTimeout
	}

	order := cfg.MethodOrder
	if len(order) == 0 {
		order = DefaultMethodOrder
	}

	// Build factory map from non-nil configs using map-based dispatch.
	factories := make(map[Method]methodFactory)

	if cfg.DANE != nil {
		daneCfg := cfg.DANE
		factories[MethodDANE] = func() (Bootstrapper, error) {
			return NewDANEBootstrapper(daneCfg)
		}
	}
	if cfg.Noise != nil {
		noiseCfg := cfg.Noise
		factories[MethodNoise] = func() (Bootstrapper, error) {
			return NewNoiseBootstrapper(noiseCfg)
		}
	}
	if cfg.SPKI != nil {
		spkiCfg := cfg.SPKI
		factories[MethodSPKI] = func() (Bootstrapper, error) {
			return NewSPKIBootstrapper(spkiCfg)
		}
	}
	if cfg.Direct != nil {
		directCfg := cfg.Direct
		factories[MethodDirect] = func() (Bootstrapper, error) {
			return NewDirectBootstrapper(directCfg)
		}
	}

	// Verify at least one method in the order has a factory.
	hasMethod := false
	for _, m := range order {
		if _, ok := factories[m]; ok {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return nil, ErrNoMethodsConfigured
	}

	return &AutoBootstrapper{
		factories:  factories,
		order:      order,
		perTimeout: perTimeout,
		logger:     logger.With("component", "auto_bootstrapper"),
	}, nil
}

// FetchCABundle tries each configured bootstrap method in priority order
// and returns the first successful result. If all methods fail, an
// AggregateError is returned wrapping ErrAllMethodsFailed.
func (b *AutoBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	attempts := make([]AttemptError, 0, len(b.order))

	for _, method := range b.order {
		// Check for context cancellation between attempts.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: context cancelled: %w", ErrAllMethodsFailed, err)
		}

		factory, ok := b.factories[method]
		if !ok {
			b.logger.Debug("skipping unconfigured method", "method", method)
			continue
		}

		b.logger.Info("attempting bootstrap method", "method", method)

		resp, err := b.tryMethod(ctx, method, factory, req)
		if err == nil {
			b.logger.Info("bootstrap succeeded", "method", method)
			return resp, nil
		}

		b.logger.Warn("bootstrap method failed",
			"method", method, "error", err)
		attempts = append(attempts, AttemptError{
			Method: method,
			Err:    err,
		})
	}

	if len(attempts) == 0 {
		return nil, ErrNoMethodsConfigured
	}

	return nil, &AggregateError{Attempts: attempts}
}

// Close is a no-op since bootstrappers are created and closed per attempt.
func (b *AutoBootstrapper) Close() error {
	return nil
}

// tryMethod creates a bootstrapper from the factory, applies a per-method
// timeout, and attempts to fetch the CA bundle.
func (b *AutoBootstrapper) tryMethod(
	ctx context.Context,
	method Method,
	factory methodFactory,
	req *CABundleRequest,
) (*CABundleResponse, error) {

	bootstrapper, err := factory()
	if err != nil {
		return nil, fmt.Errorf("create %s bootstrapper: %w", method, err)
	}
	defer bootstrapper.Close()

	methodCtx, cancel := context.WithTimeout(ctx, b.perTimeout)
	defer cancel()

	return bootstrapper.FetchCABundle(methodCtx, req)
}

// AutoFetch is a convenience function that creates an AutoBootstrapper,
// fetches the CA bundle, and cleans up in a single call.
func AutoFetch(ctx context.Context, cfg *AutoConfig) (*CABundleResponse, error) {
	auto, err := NewAutoBootstrapper(cfg)
	if err != nil {
		return nil, err
	}
	defer auto.Close()
	return auto.FetchCABundle(ctx, nil)
}
