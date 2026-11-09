// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"path"
	"strings"
)

// AllowRule accepts one class of lab value in the files its path pattern
// matches. It exists for the cases an inline waiver cannot reach: a whole tree
// of them, or a file whose syntax has no comments.
//
// Every field is required. A rule with no reason is rejected by
// ValidateAllowList, because the reason is the entire difference between an
// allow-list and a blindfold.
type AllowRule struct {
	// Path is a slash-separated pattern. `*` matches within one path
	// segment; a `**` segment matches any number of segments, including
	// none. An exact path matches only itself.
	Path string

	// Classes are the classes this rule accepts in those files. Naming them
	// keeps the rule narrow: a tree allowed to mention a fleet hostname is
	// not thereby allowed to hardcode the owner's home directory.
	Classes []Class

	// Reason says why publishing this value is acceptable, or who owns
	// removing it. It is printed by the allow-list report.
	Reason string
}

// DefaultAllowList is the accepted set for THIS repository. Every entry is a
// deliberate decision, and the list is meant to stay short.
//
// The release-readiness change (#75) removed the values themselves everywhere
// they appeared rather than listing them here. A value that genuinely has to
// stay is waived in place with `lab-string-ok: <reason>`, next to the line it
// explains; an entry here is for a whole tree or a file that cannot carry a
// comment, and it has to say why.
var DefaultAllowList = []AllowRule{
	{
		Path:    "internal/labstrings/*_test.go",
		Classes: []Class{ClassLabAddress, ClassLabHost},
		Reason: "The gate's own fixtures: the planted fleet addresses and " +
			"hostnames it must catch. Nothing is dialed. Owner paths are NOT " +
			"allowed here; the tests assemble that prefix at run time.",
	},
}

// ValidateAllowList reports the first unusable entry. Called by Scan, so a
// malformed rule fails the gate instead of quietly widening it.
func ValidateAllowList(rules []AllowRule) error {
	known := make(map[Class]bool, len(classes))
	for _, c := range classes {
		known[c] = true
	}
	for i, r := range rules {
		switch {
		case r.Path == "":
			return &AllowRuleError{Index: i, Problem: "no path pattern"}
		case strings.TrimSpace(r.Reason) == "":
			return &AllowRuleError{Index: i, Path: r.Path, Problem: "no reason given"}
		case len(r.Classes) == 0:
			return &AllowRuleError{Index: i, Path: r.Path, Problem: "no classes listed"}
		}
		for _, c := range r.Classes {
			if !known[c] {
				return &AllowRuleError{Index: i, Path: r.Path, Problem: "unknown class " + string(c)}
			}
		}
		if err := validatePattern(r.Path); err != nil {
			return &AllowRuleError{Index: i, Path: r.Path, Problem: "malformed path pattern: " + err.Error()}
		}
	}
	return nil
}

// validatePattern checks every segment of a path pattern up front. Matching
// stops at the first segment that does not match, so a malformed segment
// further along would otherwise never be evaluated -- and a pattern that can
// never match is a rule that silently does nothing.
func validatePattern(pattern string) error {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "probe"); err != nil {
			return err
		}
	}
	return nil
}

// acceptedClasses collects the classes the allow-list accepts for one file.
// Patterns are already validated by the time this runs, so a malformed pattern
// cannot silently match nothing.
func acceptedClasses(rules []AllowRule, name string) map[Class]bool {
	accepted := make(map[Class]bool, len(classes))
	for _, r := range rules {
		ok, err := matchSegments(strings.Split(r.Path, "/"), strings.Split(name, "/"))
		if err != nil || !ok {
			continue
		}
		for _, c := range r.Classes {
			accepted[c] = true
		}
	}
	return accepted
}

// MatchPath reports whether a slash-separated path matches an AllowRule pattern.
// It is exported because the allow-list is only auditable if the matching it
// relies on can be asserted directly.
func MatchPath(pattern, name string) (bool, error) {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegments walks pattern and path segment by segment. `**` is the only
// construct that may span a separator, which is what keeps a rule for one
// directory from reaching into its siblings.
func matchSegments(pattern, segments []string) (bool, error) {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			if len(pattern) == 1 {
				return true, nil
			}
			for i := 0; i <= len(segments); i++ {
				ok, err := matchSegments(pattern[1:], segments[i:])
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
			return false, nil
		}
		if len(segments) == 0 {
			return false, nil
		}
		ok, err := matchSegment(pattern[0], segments[0])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		pattern, segments = pattern[1:], segments[1:]
	}
	return len(segments) == 0, nil
}

// matchSegment matches one pattern segment against one path segment. `*` and
// `?` and character classes come from path.Match; a malformed class is reported
// rather than silently matching nothing.
func matchSegment(pattern, segment string) (bool, error) {
	ok, err := path.Match(pattern, segment)
	if err != nil {
		return false, err
	}
	return ok, nil
}
