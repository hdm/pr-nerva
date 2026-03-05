// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scan

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// BenchmarkScanPool_Sequential measures throughput with a single worker (sequential processing).
// 100 targets, Workers=1, 1ms simulated work per target.
func BenchmarkScanPool_Sequential(b *testing.B) {
	pool := NewScanPool(Config{Workers: 1})
	targets := makeTargets(100)
	fn := func(t plugins.Target) ([]plugins.Service, error) {
		time.Sleep(1 * time.Millisecond)
		return []plugins.Service{{IP: t.Address.Addr().String(), Port: int(t.Address.Port())}}, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Run(context.Background(), targets, fn)
	}
}

// BenchmarkScanPool_Parallel50 measures throughput with 50 workers against 100 targets.
// 100 targets, Workers=50, 1ms simulated work per target.
func BenchmarkScanPool_Parallel50(b *testing.B) {
	pool := NewScanPool(Config{Workers: 50})
	targets := makeTargets(100)
	fn := func(t plugins.Target) ([]plugins.Service, error) {
		time.Sleep(1 * time.Millisecond)
		return []plugins.Service{{IP: t.Address.Addr().String(), Port: int(t.Address.Port())}}, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Run(context.Background(), targets, fn)
	}
}

// BenchmarkScanPool_1000Targets measures throughput at scale: 1000 targets with 50 workers.
// 1000 targets, Workers=50, 1ms simulated work per target.
func BenchmarkScanPool_1000Targets(b *testing.B) {
	pool := NewScanPool(Config{Workers: 50})
	targets := makeTargets(1000)
	fn := func(t plugins.Target) ([]plugins.Service, error) {
		time.Sleep(1 * time.Millisecond)
		return []plugins.Service{{IP: t.Address.Addr().String(), Port: int(t.Address.Port())}}, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Run(context.Background(), targets, fn)
	}
}

// BenchmarkScanPool_WithHostLimiter measures overhead introduced by per-host connection limits.
// 100 targets, Workers=50, MaxHostConn=5, 1ms simulated work per target.
// All targets share IP 127.0.0.1 (via makeTargets), so the host limiter is actively exercised.
func BenchmarkScanPool_WithHostLimiter(b *testing.B) {
	pool := NewScanPool(Config{
		Workers:     50,
		MaxHostConn: 5,
	})
	targets := makeTargets(100)
	fn := func(t plugins.Target) ([]plugins.Service, error) {
		time.Sleep(1 * time.Millisecond)
		return []plugins.Service{{IP: t.Address.Addr().String(), Port: int(t.Address.Port())}}, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Run(context.Background(), targets, fn)
	}
}

// BenchmarkScanPool_WithRateLimiter measures overhead introduced by the global rate limiter
// with an instant scan function (no simulated work) so that token-wait time dominates.
// 20 targets, Workers=50, RateLimit=100.0 (100/s → ~10ms between tokens).
func BenchmarkScanPool_WithRateLimiter(b *testing.B) {
	pool := NewScanPool(Config{
		Workers:   50,
		RateLimit: 100.0,
	})
	targets := makeTargets(20)
	fn := func(t plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: t.Address.Addr().String(), Port: int(t.Address.Port())}}, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Run(context.Background(), targets, fn)
	}
}
