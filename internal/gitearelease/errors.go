// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package gitearelease

import (
	"errors"
	"strconv"
)

// ErrNoNotes is the category of every *NoNotesError, so a caller that only
// needs the category can test with errors.Is.
var ErrNoNotes = errors.New("gitearelease: no CHANGELOG section for the release")

// ErrAssetsFailed is the category of every *AssetsFailedError.
var ErrAssetsFailed = errors.New("gitearelease: one or more assets failed to upload")

// NoNotesError is returned when CHANGELOG.md has no non-empty section for the
// version being released. The release workflow's validate job proves the
// heading exists before this runs, so reaching it is a bug, not a routine case.
type NoNotesError struct {
	// Version is the version whose section is absent or empty, without the
	// leading "v" of its tag.
	Version string
}

func (e *NoNotesError) Error() string {
	return "gitearelease: no CHANGELOG section for the release " + e.Version
}

// Is reports ErrNoNotes as this error's category.
func (e *NoNotesError) Is(target error) bool { return target == ErrNoNotes }

// AssetsFailedError is returned when one or more assets did not upload. Every
// asset is attempted before it is returned, so the log names each failure.
type AssetsFailedError struct {
	// Failed is how many assets did not upload.
	Failed int

	// Total is how many assets were attempted.
	Total int
}

func (e *AssetsFailedError) Error() string {
	return "gitearelease: " + strconv.Itoa(e.Failed) + " of " + strconv.Itoa(e.Total) +
		" assets failed to upload"
}

// Is reports ErrAssetsFailed as this error's category.
func (e *AssetsFailedError) Is(target error) bool { return target == ErrAssetsFailed }

// ConfigError names a required setting that is missing.
type ConfigError struct {
	// Field is the environment variable (or Config field) that is empty.
	Field string
}

func (e *ConfigError) Error() string {
	return "gitearelease: " + e.Field + " is required"
}

// APIError is a Gitea API call that did not answer as expected. It carries
// the method and the path -- never the token, which travels in a header and
// is not part of either.
type APIError struct {
	// Method is the HTTP method.
	Method string

	// Path is the request path under the server URL.
	Path string

	// Status is the HTTP status code, or 0 when no response arrived.
	Status int

	// Detail is the response body (bounded) or the transport failure.
	Detail string

	// Err is the underlying transport or decoding error, if any.
	Err error
}

func (e *APIError) Error() string {
	msg := "gitearelease: " + e.Method + " " + e.Path
	if e.Status != 0 {
		msg += ": HTTP " + strconv.Itoa(e.Status)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.Err }

// AssetError is a dist/ file that could not be read for upload.
type AssetError struct {
	// Path is the file.
	Path string

	// Err is the underlying I/O failure.
	Err error
}

func (e *AssetError) Error() string {
	return "gitearelease: asset " + e.Path + ": " + e.Err.Error()
}

func (e *AssetError) Unwrap() error { return e.Err }
