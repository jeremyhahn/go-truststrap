// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import "strconv"

// The gate distinguishes "this tree has a violation" from "this gate could not
// run", so each way it can fail to run is its own type carrying what a caller
// needs to fix it. A finding is a value, never an error.

// ListError is returned when the tracked-file enumeration fails. The gate reads
// the git index because that is the ship manifest, so a tree with no index -- an
// extracted tarball, a module cache entry -- cannot be gated, and says so.
type ListError struct {
	// Root is the directory git was asked about.
	Root string

	// Stderr is what git said, which is the only thing that distinguishes
	// "not a work tree" from "git is not installed".
	Stderr string

	// Err is the underlying exec failure.
	Err error
}

func (e *ListError) Error() string {
	msg := "labstrings: cannot list tracked files in " + e.Root + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *ListError) Unwrap() error { return e.Err }

// ReadError is returned when a tracked file exists but cannot be read to its
// end. Every file is scanned whatever its size or content, and only a file absent
// from the working tree is skipped, so this is never a silent pass.
type ReadError struct {
	// Path is the file that could not be read.
	Path string

	// Err is the underlying I/O failure.
	Err error
}

func (e *ReadError) Error() string {
	return "labstrings: cannot read " + e.Path + ": " + e.Err.Error()
}

func (e *ReadError) Unwrap() error { return e.Err }

// AllowRuleError is returned when an allow-list entry is not usable. An
// allow-list is the gate's own configuration: a malformed or unexplained entry
// silently accepts whatever it covers, so it fails the gate instead.
type AllowRuleError struct {
	// Index is the entry's position in the list.
	Index int

	// Path is the entry's path pattern, empty if that is the defect.
	Path string

	// Problem says what is wrong with the entry.
	Problem string
}

func (e *AllowRuleError) Error() string {
	return "labstrings: allow-list entry " + strconv.Itoa(e.Index) + " (" + e.Path + "): " + e.Problem
}

// ReportError is returned when the report cannot be written. The report is the
// gate's product, so a silent write failure would turn a failing gate into a
// passing one.
type ReportError struct {
	// Err is the underlying write failure.
	Err error
}

func (e *ReportError) Error() string {
	return "labstrings: cannot write report: " + e.Err.Error()
}

func (e *ReportError) Unwrap() error { return e.Err }

// ExemptionError is returned when an entry of the exemption list is not usable.
// Like an allow-list entry, an unexplained or duplicated exemption would
// silently widen the gate, so it fails it instead.
type ExemptionError struct {
	// Line is the entry's 1-based line in the exemption file.
	Line int

	// Path is the entry's path.
	Path string

	// Problem says what is wrong with the entry.
	Problem string
}

func (e *ExemptionError) Error() string {
	return "labstrings: " + ExemptFile + ":" + strconv.Itoa(e.Line) + " (" + e.Path + "): " + e.Problem
}
