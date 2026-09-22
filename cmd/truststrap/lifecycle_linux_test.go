// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// The binary's protected-memory lifecycle is two promises run() makes: install
// the process budget BEFORE any command can allocate against it, and sweep
// every enclave still held once the command returns -- on success AND on
// failure, since the failure path is the one an early os.Exit would skip.
//
// Both are process-scoped and one-shot (SetAllocator refuses a second install,
// and a lazily installed default counts as the first), so neither can be
// observed from inside this test process once any other test has touched the
// allocator. Each case therefore re-executes this test binary, which TestMain
// routes straight to the helper: a fresh process in which run() is the first
// thing to reach go-enclave, exactly as it is in the shipped binary.

const (
	// lifecycleHelperEnv selects the helper and carries the mode it runs in.
	lifecycleHelperEnv = "TRUSTSTRAP_LIFECYCLE_HELPER"

	lifecycleModeSuccess = "success"
	lifecycleModeFailure = "failure"

	// lifecycleReportPrefix marks the helper's one line of result on stdout,
	// so logging and cobra output around it cannot be mistaken for it.
	lifecycleReportPrefix = "LIFECYCLE-REPORT "

	// lifecycleProbeCommand is the subcommand the helper registers to stand in
	// for a real command: it allocates through the process allocator and holds
	// what it allocated past its own return, as a command that leaked key
	// material would.
	lifecycleProbeCommand = "lifecycle-probe"

	// lifecycleMemlockCeiling is the RLIMIT_MEMLOCK the helper pins itself to,
	// so the budget it expects does not depend on the host's configuration and
	// is distinguishable from go-enclave's lazy default (the whole ceiling).
	lifecycleMemlockCeiling = 8 << 20
)

// errLifecycleProbe is the failure the probe command returns in failure mode.
var errLifecycleProbe = errors.New("lifecycle probe: deliberate command failure")

// lifecycleReport is what the helper process observed.
type lifecycleReport struct {
	// SetupErr, when set, is why the helper could not set up a meaningful run.
	SetupErr string `json:"setup_err,omitempty"`

	// ExpectedBudget is lockedMemoryBudget over the ceiling the helper saw.
	ExpectedBudget int64 `json:"expected_budget"`
	// DefaultBudget is what go-enclave's lazy default would have installed
	// over the same ceiling: the value a missing installation would show.
	DefaultBudget int64 `json:"default_budget"`
	// ObservedBudget is the process allocator's limit as the command saw it.
	ObservedBudget int64 `json:"observed_budget"`

	// Allocated reports that the probe held a live enclave when it returned.
	Allocated bool `json:"allocated"`
	// AliveAfterRun reports whether that enclave survived run() returning.
	AliveAfterRun bool `json:"alive_after_run"`

	ExitCode int    `json:"exit_code"`
	ProbeErr string `json:"probe_err,omitempty"`
}

func TestRun_ProtectedMemoryLifecycle(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		wantExit int
	}{
		{name: "a command that succeeds", mode: lifecycleModeSuccess, wantExit: ExitSuccess},
		{name: "a command that fails", mode: lifecycleModeFailure, wantExit: ExitFetchFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := runLifecycleHelper(t, tt.mode)
			if report.SetupErr != "" {
				t.Fatalf("the lifecycle helper could not set up a meaningful run: %s", report.SetupErr)
			}

			if report.ProbeErr != "" {
				t.Fatalf("the probe command could not allocate: %s", report.ProbeErr)
			}

			// Installation happened, and happened before the command ran.
			if report.ExpectedBudget == report.DefaultBudget {
				t.Fatalf("expected budget %d equals the lazy default; the case cannot tell installation from its absence",
					report.ExpectedBudget)
			}
			if report.ObservedBudget != report.ExpectedBudget {
				t.Errorf("the command saw a process budget of %d, want the installed %d (the lazy default would be %d)",
					report.ObservedBudget, report.ExpectedBudget, report.DefaultBudget)
			}

			// The sweep ran, on this exit path too.
			if !report.Allocated {
				t.Fatal("the probe command never held a live enclave, so the sweep was not exercised")
			}
			if report.AliveAfterRun {
				t.Error("an enclave the command still held survived run() returning; the shutdown sweep did not run")
			}

			if report.ExitCode != tt.wantExit {
				t.Errorf("run() = %d, want %d", report.ExitCode, tt.wantExit)
			}
		})
	}
}

// runLifecycleHelper re-executes this test binary as the helper in mode and
// returns what it reported.
func runLifecycleHelper(t *testing.T, mode string) lifecycleReport {
	t.Helper()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	cmd := exec.Command(self, "-test.run=^$") //#nosec G204 -- re-executes this test binary itself; no argument is external input
	cmd.Env = append(os.Environ(), lifecycleHelperEnv+"="+mode)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lifecycle helper failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, lifecycleReportPrefix)
		if idx < 0 {
			continue
		}
		var report lifecycleReport
		if err := json.Unmarshal([]byte(line[idx+len(lifecycleReportPrefix):]), &report); err != nil {
			t.Fatalf("lifecycle helper report is not valid JSON: %v\nline: %s", err, line)
		}
		return report
	}
	t.Fatalf("lifecycle helper produced no report\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	return lifecycleReport{}
}

// TestMain routes a process launched by runLifecycleHelper to the helper
// before any test runs, so run() is the first thing in that process to reach
// go-enclave. Every other invocation runs the tests as usual.
func TestMain(m *testing.M) {
	if mode := os.Getenv(lifecycleHelperEnv); mode != "" {
		os.Exit(writeLifecycleReport(lifecycleHelper(mode)))
	}
	os.Exit(m.Run())
}

// writeLifecycleReport prints report as the helper's one result line and
// returns the helper process's exit code.
func writeLifecycleReport(report lifecycleReport) int {
	encoded, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode lifecycle report: %v\n", err)
		return 1
	}
	if _, err := os.Stdout.WriteString(lifecycleReportPrefix + string(encoded) + "\n"); err != nil {
		return 1
	}
	return 0
}

// lifecycleHelper pins the ceiling, runs run() over a probe command, and
// reports what the command and the process saw. Nothing in it touches the
// process allocator before run() does.
func lifecycleHelper(mode string) lifecycleReport {
	var report lifecycleReport

	// Lowering one's own soft limit needs no privilege. It is capped at the
	// hard limit, which an unprivileged process cannot raise.
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		report.SetupErr = "cannot read RLIMIT_MEMLOCK: " + err.Error()
		return report
	}
	rl.Cur = min(uint64(lifecycleMemlockCeiling), rl.Max)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		report.SetupErr = "cannot set RLIMIT_MEMLOCK: " + err.Error()
		return report
	}

	limit, err := enclave.DiscoverLockedMemoryLimit()
	if err != nil {
		report.SetupErr = "cannot discover the locked-memory limit: " + err.Error()
		return report
	}
	report.ExpectedBudget = lockedMemoryBudget(limit)
	if report.ExpectedBudget <= 0 {
		report.SetupErr = "the host's hard RLIMIT_MEMLOCK leaves no budget to install"
		return report
	}
	report.DefaultBudget = math.MaxInt64
	if limit.Bounded {
		report.DefaultBudget = limit.Bytes
	}

	var held *enclave.MemoryEnclave
	probe := &cobra.Command{
		Use: lifecycleProbeCommand,
		RunE: func(*cobra.Command, []string) error {
			allocator, err := enclave.ProcessAllocator()
			if err != nil {
				report.ProbeErr = err.Error()
				return err
			}
			report.ObservedBudget = allocator.Limit()

			held, err = allocator.New([]byte("lifecycle probe key material"))
			if err != nil {
				report.ProbeErr = err.Error()
				return err
			}
			report.Allocated = held.IsAlive()

			if mode == lifecycleModeFailure {
				return errLifecycleProbe
			}
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	rootCmd.SetArgs([]string{lifecycleProbeCommand})

	report.ExitCode = run()
	if held != nil {
		report.AliveAfterRun = held.IsAlive()
	}
	return report
}
