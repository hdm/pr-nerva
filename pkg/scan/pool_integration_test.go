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
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// startMockServer starts a TCP listener on a random loopback port. On each
// accepted connection it optionally waits delay, then writes "MOCK SERVICE\n"
// and closes. The returned cleanup function stops the listener.
func startMockServer(t *testing.T, delay time.Duration) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if delay > 0 {
					time.Sleep(delay)
				}
				c.Write([]byte("MOCK SERVICE\n"))
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(addr.Port))
	return ap, func() { ln.Close() }
}

// TestIntegration_ScanPool_MockServers starts 10 mock TCP listeners and runs
// the pool with Workers=5. The scanFunc performs a real TCP dial and reads the
// banner; we assert that all 10 targets are detected.
func TestIntegration_ScanPool_MockServers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	const numServers = 10

	targets := make([]plugins.Target, numServers)
	for i := 0; i < numServers; i++ {
		ap, cleanup := startMockServer(t, 0)
		t.Cleanup(cleanup)
		targets[i] = plugins.Target{Address: ap}
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		conn, err := net.DialTimeout("tcp", target.Address.String(), 5*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			return nil, scanner.Err()
		}
		banner := strings.TrimSpace(scanner.Text())

		return []plugins.Service{{
			IP:       target.Address.Addr().String(),
			Port:     int(target.Address.Port()),
			Protocol: banner,
		}}, nil
	}

	pool := NewScanPool(Config{Workers: 5})
	results, err := pool.Run(context.Background(), targets, fn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != numServers {
		t.Errorf("expected %d detected services, got %d", numServers, len(results))
	}
	for _, svc := range results {
		if svc.Protocol != "MOCK SERVICE" {
			t.Errorf("expected banner %q, got %q for %s:%d", "MOCK SERVICE", svc.Protocol, svc.IP, svc.Port)
		}
	}
}

// TestIntegration_ScanPool_WorkerScaling starts 20 mock TCP listeners that each
// impose a 50 ms response delay. It runs the pool twice — Workers=1 and Workers=10
// — and asserts that the 10-worker run completes at least 3x faster.
func TestIntegration_ScanPool_WorkerScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	const numServers = 20
	const responseDelay = 50 * time.Millisecond

	targets := make([]plugins.Target, numServers)
	for i := 0; i < numServers; i++ {
		ap, cleanup := startMockServer(t, responseDelay)
		t.Cleanup(cleanup)
		targets[i] = plugins.Target{Address: ap}
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		conn, err := net.DialTimeout("tcp", target.Address.String(), 5*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			return nil, scanner.Err()
		}

		return []plugins.Service{{
			IP:   target.Address.Addr().String(),
			Port: int(target.Address.Port()),
		}}, nil
	}

	// Single worker: all 20 targets are processed sequentially, each taking
	// at least 50 ms, so total >= 1000 ms.
	singlePool := NewScanPool(Config{Workers: 1})
	start := time.Now()
	_, err := singlePool.Run(context.Background(), targets, fn)
	singleDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Workers=1 run returned error: %v", err)
	}

	// Ten workers: targets are processed in parallel batches, so total should
	// be around 100–200 ms (2 batches of 10 × 50 ms).
	tenPool := NewScanPool(Config{Workers: 10})
	start = time.Now()
	_, err = tenPool.Run(context.Background(), targets, fn)
	tenDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Workers=10 run returned error: %v", err)
	}

	const speedupFactor = 3
	if singleDuration < tenDuration*speedupFactor {
		t.Errorf(
			"expected Workers=10 to be at least %dx faster than Workers=1: "+
				"single=%v ten=%v (ratio=%.1f)",
			speedupFactor,
			singleDuration,
			tenDuration,
			float64(singleDuration)/float64(tenDuration),
		)
	}
}

// TestIntegration_ScanPool_RateLimitedMockServer starts 5 mock TCP listeners and
// runs the pool with Workers=10, RateLimit=10.0 (100 ms/token). With 5 targets the
// first is free and the remaining 4 each consume one token; total elapsed must be
// >= 350 ms (4 intervals × 100 ms, with a 50 ms tolerance).
func TestIntegration_ScanPool_RateLimitedMockServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	const numServers = 5

	targets := make([]plugins.Target, numServers)
	for i := 0; i < numServers; i++ {
		ap, cleanup := startMockServer(t, 0)
		t.Cleanup(cleanup)
		targets[i] = plugins.Target{Address: ap}
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		conn, err := net.DialTimeout("tcp", target.Address.String(), 5*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			return nil, scanner.Err()
		}

		return []plugins.Service{{
			IP:   target.Address.Addr().String(),
			Port: int(target.Address.Port()),
		}}, nil
	}

	pool := NewScanPool(Config{
		Workers:   10,
		RateLimit: 10.0, // 10 tokens/s → 100 ms between tokens
	})

	start := time.Now()
	results, err := pool.Run(context.Background(), targets, fn)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) != numServers {
		t.Errorf("expected %d results, got %d", numServers, len(results))
	}

	// 5 targets at 10/s: first is free, then 4 × 100 ms = 400 ms minimum.
	// Allow 350 ms to avoid CI flakiness (same threshold as existing unit test).
	const minElapsed = 350 * time.Millisecond
	if elapsed < minElapsed {
		t.Errorf(
			"expected elapsed >= %v with RateLimit=10, got %v — rate limiter may not be enforced",
			minElapsed,
			elapsed,
		)
	}
}
