#!/usr/bin/env python3
"""automerge-approvers-tests.py -- runs the approver-list check of automerge.yml
(v13.2) as the workflow runs it and asserts which lists it accepts.

The code under test is read out of the workflow file, not copied: the jq
program that sets EFFECTIVE_APPROVERS, the `APPROVERS=${APPROVERS:-[]}`
default before it, and the fail-closed test after it. Each marker must be
found exactly once, or the test stops with FATAL (exit 9) and measures
nothing. The program runs under jq with the two repository variables as the
workflow passes them (`--arg base`, `--arg only`); nothing reaches the network.

  A. AUTOMERGE_APPROVERS_ONLY unset, so AUTOMERGE_APPROVERS is selected:
     1. a JSON array of logins: accepted, sorted and de-duplicated;
     2. the regression (v13.1, Company Agent m2355 item 2a): a JSON string
        scalar such as "codex" FAILS CLOSED; under v13.1 it passed unchecked
        and jq index() on it is a substring match, so "code" was an approver;
     3. a number, an object, null, true, an empty array, an array holding a
        non-string, text that is not JSON, and the empty default `[]`: each
        FAILS CLOSED.
  B. AUTOMERGE_APPROVERS_ONLY set, so it replaces the list (v9):
     1. a JSON array of logins: accepted alone, whatever AUTOMERGE_APPROVERS
        holds;
     2. a scalar, an empty array, an array holding a non-string, and text that
        is not JSON: each FAILS CLOSED.
  C. On every accepted list, the approval check's `$ok | index($u)` admits an
     exact login and refuses a prefix of one.

Run: python3 -I software/templates/github-actions/testdata/automerge-approvers-tests.py
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = HERE.parent / "automerge.yml"
INVALID = "__invalid__"


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def once(pattern, text, what):
    found = re.findall(pattern, text, re.S)
    if len(found) != 1:
        fatal(f"{what}: found {len(found)} times in {WORKFLOW.name}, want 1")
    return found[0]


def main():
    if shutil.which("jq") is None:
        fatal("jq is not on PATH")
    src = WORKFLOW.read_text()
    once(r'\n *APPROVERS=\$\{APPROVERS:-\[\]\}\n', src, "the APPROVERS default")
    once(r'\[ "\$EFFECTIVE_APPROVERS" != \'"__invalid__"\' \] \|\|\n *die ', src,
         "the fail-closed test")
    program = once(
        r'EFFECTIVE_APPROVERS=\$\(jq -nc --arg base "\$APPROVERS" '
        r'--arg only "\$\{APPROVERS_ONLY:-\}" \'\n(.*?)\'\)\n',
        src, "the EFFECTIVE_APPROVERS jq program")

    def effective(base, only=""):
        base = base if base != "" else "[]"  # APPROVERS=${APPROVERS:-[]}
        out = subprocess.run(
            ["jq", "-nc", "--arg", "base", base, "--arg", "only", only, program],
            capture_output=True, text=True, check=False)
        if out.returncode != 0:
            return ("jq-error", out.stderr.strip())
        return json.loads(out.stdout)

    def admits(ok, login):
        out = subprocess.run(
            ["jq", "-nc", "--arg", "u", login, "--argjson", "ok", json.dumps(ok),
             "$ok | index($u) != null"],
            capture_output=True, text=True, check=True)
        return out.stdout.strip() == "true"

    fails = 0
    total = 0

    def check(name, got, want):
        nonlocal fails, total
        total += 1
        if got == want:
            print(f"ok   {name}")
        else:
            fails += 1
            print(f"FAIL {name}: got {got!r}, want {want!r}")

    # A. the base list is selected.
    check("A1 array accepted", effective('["codex","claude","codex"]'),
          ["claude", "codex"])
    check("A2 scalar string fails closed", effective('"codex"'), INVALID)
    for name, value in [("number", "7"), ("object", '{"a":"codex"}'),
                        ("null", "null"), ("true", "true"),
                        ("empty array", "[]"), ("non-string member", '["codex",1]'),
                        ("not JSON", "codex"), ("unset (default [])", "")]:
        check(f"A3 {name} fails closed", effective(value), INVALID)

    # B. the override replaces the base.
    check("B1 override accepted alone", effective('"codex"', '["infra"]'), ["infra"])
    check("B1 override over a valid base", effective('["codex"]', '["infra"]'), ["infra"])
    for name, value in [("scalar", '"infra"'), ("empty array", "[]"),
                        ("non-string member", '["infra",null]'), ("not JSON", "infra")]:
        check(f"B2 override {name} fails closed", effective('["codex"]', value), INVALID)

    # C. the approval check on an accepted list is exact.
    ok = effective('["codex","claude"]')
    check("C exact login admitted", admits(ok, "codex"), True)
    check("C prefix refused", admits(ok, "code"), False)

    print(f"{total - fails} of {total} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
