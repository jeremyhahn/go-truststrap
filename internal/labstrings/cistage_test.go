// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stagingStepName is the ci.yml step that stages the labstrings patterns file.
const stagingStepName = "      - name: Stage the labstrings patterns file"

// stagingScript returns the `run: |` body of the staging step in ci.yml, with
// the block's ten-space indent stripped, as the runner hands it to bash.
func stagingScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	step := -1
	for i, line := range lines {
		if line == stagingStepName {
			if step >= 0 {
				t.Fatalf("%s names the step %q more than once", path, strings.TrimSpace(stagingStepName))
			}
			step = i
		}
	}
	if step < 0 {
		t.Fatalf("%s has no step %q", path, strings.TrimSpace(stagingStepName))
	}
	run := -1
	for i := step + 1; i < len(lines); i++ {
		if lines[i] == "        run: |" {
			run = i
			break
		}
	}
	if run < 0 {
		t.Fatalf("the step %q has no `run: |` line", strings.TrimSpace(stagingStepName))
	}
	const indent = "          "
	var body []string
	for _, line := range lines[run+1:] {
		if strings.TrimSpace(line) == "" {
			body = append(body, "")
			continue
		}
		if !strings.HasPrefix(line, indent) {
			break
		}
		body = append(body, strings.TrimPrefix(line, indent))
	}
	script := strings.TrimRight(strings.Join(body, "\n"), "\n")
	if strings.TrimSpace(script) == "" {
		t.Fatalf("the step %q has an empty script", strings.TrimSpace(stagingStepName))
	}
	return script + "\n"
}

// TestCIStagingStep_GuardsTheEmptySecret answers Codex round 4 on #109: the
// ci.yml step that stages the labstrings patterns file had no test of its
// empty-secret guard. The script is read out of the workflow, not copied, so
// a change to the step is tested as it ships, and it runs the way GitHub
// Actions runs a `run:` step, with nothing of this process's environment but
// PATH.
func TestCIStagingStep_GuardsTheEmptySecret(t *testing.T) {
	script := stagingScript(t)
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("the staging step runs under bash, which is not on PATH: %v", err)
	}
	scriptFile := filepath.Join(t.TempDir(), "stage.sh")
	if err := os.WriteFile(scriptFile, []byte(script), 0o600); err != nil {
		t.Fatalf("writing the script: %v", err)
	}

	const patterns = "example-pattern-1\nexample-pattern-2"
	cases := []struct {
		name      string
		patterns  string
		event     string
		ref       string
		wantExit  int
		wantOut   string
		wantStage bool
	}{
		{
			name:     "empty secret on a push to main fails",
			event:    "push",
			ref:      "refs/heads/main",
			wantExit: 1,
			wantOut:  "::error::RELEASABILITY_PATTERNS is empty on a push to main",
		},
		{
			name:     "empty secret on a pull request passes without a file",
			event:    "pull_request",
			ref:      "refs/pull/7/merge",
			wantOut:  "the labstrings gate runs without a patterns file",
			wantExit: 0,
		},
		{
			name:     "empty secret on a push to another branch passes without a file",
			event:    "push",
			ref:      "refs/heads/feature",
			wantExit: 0,
		},
		{
			name:      "set secret on a push to main is staged",
			patterns:  patterns,
			event:     "push",
			ref:       "refs/heads/main",
			wantStage: true,
		},
		{
			name:      "set secret on a pull request is staged",
			patterns:  patterns,
			event:     "pull_request",
			ref:       "refs/pull/7/merge",
			wantStage: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runnerTemp := t.TempDir()
			githubEnv := filepath.Join(t.TempDir(), "github_env")
			if err := os.WriteFile(githubEnv, nil, 0o600); err != nil {
				t.Fatalf("creating GITHUB_ENV: %v", err)
			}
			cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", scriptFile)
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"RELEASABILITY_PATTERNS=" + tc.patterns,
				"GITHUB_EVENT_NAME=" + tc.event,
				"GITHUB_REF=" + tc.ref,
				"RUNNER_TEMP=" + runnerTemp,
				"GITHUB_ENV=" + githubEnv,
			}
			out, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("running the step: %v", err)
				}
				exit = exitErr.ExitCode()
			}
			if exit != tc.wantExit {
				t.Fatalf("exit status %d, want %d; output:\n%s", exit, tc.wantExit, out)
			}
			if tc.wantOut != "" && !strings.Contains(string(out), tc.wantOut) {
				t.Errorf("output does not contain %q:\n%s", tc.wantOut, out)
			}
			if strings.Contains(string(out), "example-pattern") {
				t.Errorf("the step echoed the secret:\n%s", out)
			}

			env, err := os.ReadFile(githubEnv)
			if err != nil {
				t.Fatalf("reading GITHUB_ENV: %v", err)
			}
			staged := filepath.Join(runnerTemp, "labstrings-patterns")
			if !tc.wantStage {
				if len(env) != 0 {
					t.Errorf("GITHUB_ENV = %q, want it empty", env)
				}
				if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s exists (or cannot be checked: %v), want no patterns file", staged, err)
				}
				return
			}
			if want := "LABSTRINGS_PATTERNS=" + staged + "\n"; string(env) != want {
				t.Errorf("GITHUB_ENV = %q, want %q", env, want)
			}
			got, err := os.ReadFile(staged)
			if err != nil {
				t.Fatalf("reading the patterns file: %v", err)
			}
			if string(got) != tc.patterns {
				t.Errorf("patterns file holds %q, want %q", got, tc.patterns)
			}
			info, err := os.Stat(staged)
			if err != nil {
				t.Fatalf("stat the patterns file: %v", err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("patterns file mode %#o, want 0600", mode)
			}
		})
	}
}
