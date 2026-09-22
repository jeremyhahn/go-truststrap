// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// These tests exercise the byte-budget admission that closes the measured
// connect-cost denial of service (#15/#17), now that the hand-rolled
// concurrency cap has been retired in favour of go-enclave's allocator (#19).
//
// They substitute a deliberately tiny allocator for the process one. That
// substitution is why the seam exists: the process allocator is install-once by
// design, so it cannot be shrunk and restored around a test, and a test that
// could reinstall it would be testing a contract the library does not have.

// scheduleCost is what one responder key schedule charges: the page-rounded
// cost of one scheduleSize region. The allocator charges what the KERNEL
// charges, so the arithmetic has to be in the same unit.
var scheduleCost = enclave.LockedSize(scheduleSize)

// transportKeyCost is what ONE directional transport key charges. split takes
// two of them, separately, which is the boundary the partial-allocation tests
// below aim at.
var transportKeyCost = enclave.LockedSize(hashSize)

// withScheduleHalves borrows a key schedule and hands fn its two halves -- the
// chaining key and the AEAD key -- so a test can assert on them WITHOUT either
// leaving its locked region. fn runs inside the borrow and must not retain
// either slice.
//
// This is the shape every protected-memory assertion in this package takes.
// A helper that copied the material out into an ordinary heap slice for the
// test to look at would leave an unwipeable duplicate of a live key on the Go
// heap, which is the thing the protected-memory mandate exists to prevent and
// is refused outright for tests (security-review.md section 6,
// testing-guidelines.md).
func withScheduleHalves(t *testing.T, s *symmetricState, fn func(ck, k []byte)) {
	t.Helper()

	if err := s.withSchedule("test", func(ck, k []byte) error {
		fn(ck, k)
		return nil
	}); err != nil {
		t.Fatalf("borrowing the key schedule: %v", err)
	}
}

// withBudget substitutes an allocator of exactly this many locked bytes for the
// process allocator, for one test, and asserts on the way out that the test
// returned every byte it took. That leak check is the package's only detector
// for an unreleased reservation: the protocol behaves identically whether or
// not the pages come back.
func withBudget(t *testing.T, bytes int64) *enclave.Allocator {
	t.Helper()

	allocator, err := enclave.NewAllocator(bytes)
	if err != nil {
		t.Fatalf("enclave.NewAllocator(%d): %v", bytes, err)
	}

	prev := processAllocator
	processAllocator = func() (*enclave.Allocator, error) { return allocator, nil }

	t.Cleanup(func() {
		processAllocator = prev
		if inUse := allocator.InUse(); inUse != 0 {
			t.Errorf("this test leaked %d locked bytes", inUse)
		}
	})

	return allocator
}

// message1 produces a valid message 1 for static, and the initiator that wrote
// it. It runs BEFORE any budget substitution in these tests, so the initiator's
// own schedule is charged to the real process allocator and does not eat the
// budget under test -- the responder is the side being squeezed.
func message1(t *testing.T, static *StaticKey) (*Initiator, []byte) {
	t.Helper()

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	msg, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}

	return i, msg
}

// admitResponder runs ReadMessage1 to completion for a responder that must be
// admitted, and returns it holding its schedule.
func admitResponder(t *testing.T, static *StaticKey, msg []byte) *Responder {
	t.Helper()

	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	if err := r.ReadMessage1(msg); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}

	return r
}

// The core property, and the one the issue's reproduction asks for: once the
// process's locked-memory budget is exhausted, a further responder fails closed
// with a typed error, locks nothing, and leaves the handshakes holding the
// budget completely untouched -- they still complete and their transport still
// works. Nothing is purged and nothing panics.
func TestResponder_ExhaustedBudgetFailsClosedWithoutDamagingActiveHandshakes(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	i1, msg1 := message1(t, static)
	defer i1.Destroy()
	i2, msg2 := message1(t, static)
	defer i2.Destroy()
	i3, msg3 := message1(t, static)
	defer i3.Destroy()
	i4, msg4 := message1(t, static)
	defer i4.Destroy()

	// Exactly three responder schedules fit.
	allocator := withBudget(t, 3*scheduleCost)

	r1 := admitResponder(t, static, msg1)
	defer r1.Destroy()
	r2 := admitResponder(t, static, msg2)
	defer r2.Destroy()
	r3 := admitResponder(t, static, msg3)
	defer r3.Destroy()

	if got := allocator.InUse(); got != 3*scheduleCost {
		t.Fatalf("locked bytes in use = %d, want %d", got, 3*scheduleCost)
	}

	// A fourth responder is refused: the budget is full. It must lock nothing,
	// charge nothing, and report the typed error rather than panicking.
	r4, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer r4.Destroy()

	refusal := r4.ReadMessage1(msg4)
	if !errors.Is(refusal, ErrProtectedMemory) {
		t.Fatalf("ReadMessage1 over the budget: got %v, want ErrProtectedMemory", refusal)
	}
	// The allocator's own sentinel is reachable too: the refusal was decided by
	// admission, BEFORE any locked memory was requested of the kernel.
	if !errors.Is(refusal, enclave.ErrBudgetExhausted) {
		t.Fatalf("ReadMessage1 over the budget: got %v, want enclave.ErrBudgetExhausted", refusal)
	}
	assertNoSchedule(t, r4.sym, "a responder refused by the budget")
	if got := allocator.InUse(); got != 3*scheduleCost {
		t.Fatalf("a refused allocation changed the bytes in use to %d, want %d", got, 3*scheduleCost)
	}

	// The refusal purged nothing: every budget-holding handshake still holds a
	// live key schedule. This is the property memguard could not offer -- its
	// exhaustion path destroyed every protected buffer in the process.
	assertScheduleHeld(t, r1.sym, "handshake 1 after another connection was refused")
	assertScheduleHeld(t, r2.sym, "handshake 2 after another connection was refused")
	assertScheduleHeld(t, r3.sym, "handshake 3 after another connection was refused")

	// Releasing connections returns their bytes, and the handshake that kept
	// its schedule completes end to end on the capacity that frees up.
	r2.Destroy()
	r3.Destroy()
	if got := allocator.InUse(); got != scheduleCost {
		t.Fatalf("after releasing two responders, bytes in use = %d, want %d", got, scheduleCost)
	}

	reply, responderTransport, err := r1.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2 after a refusal elsewhere: %v", err)
	}
	initiatorTransport, err := i1.ReadMessage2(reply)
	if err != nil {
		t.Fatalf("ReadMessage2 after a refusal elsewhere: %v", err)
	}

	ad := []byte("header")
	pt := []byte("payload")
	got, err := responderTransport.Open(sealOne(t, initiatorTransport, pt, ad), ad)
	if err != nil {
		t.Fatalf("transport Open: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("transport round-trip = %q, want %q", got, pt)
	}
}

// The reproduction from the issue: a flood of structurally valid, correctly
// tagged message 1 values against a budget that holds only two of them. Every
// refusal must be the typed exhaustion error, nothing may panic, and the budget
// must come back to zero once the flood is released.
//
// The counts here are EXACT, not "at least one of each", and the coordination
// is what makes them so. Every goroutine reports its outcome and then blocks
// until all of them have reported, so no admitted responder can give its
// reservation back while another is still competing for it. Without that hold
// the scheduler is free to run the goroutines one at a time -- each admitted,
// each releasing before the next starts -- and the test would pass with nothing
// ever refused, which is the property it exists to check.
func TestResponder_FloodUnderAConstrainedBudgetRefusesWithoutPanicking(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	const (
		flood     = 32
		capacity  = 2 // responder schedules the budget holds at once
		wantRefus = flood - capacity
	)

	msgs := make([][]byte, flood)
	for n := range msgs {
		i, msg := message1(t, static)
		msgs[n] = msg
		i.Destroy()
	}

	allocator := withBudget(t, capacity*scheduleCost)

	// outcomes collects one report per connection; release is closed only once
	// all of them are in, so an admitted responder holds its schedule for the
	// whole flood.
	type outcome struct {
		admitted bool
		err      error
	}

	outcomes := make(chan outcome, flood)
	release := make(chan struct{})

	var wg sync.WaitGroup

	for n := range msgs {
		wg.Add(1)

		go func(msg []byte) {
			defer wg.Done()

			r, err := NewResponder(static)
			if err != nil {
				outcomes <- outcome{err: err}
				<-release

				return
			}

			readErr := r.ReadMessage1(msg)
			outcomes <- outcome{admitted: readErr == nil, err: readErr}

			// Hold whatever was admitted until every other connection has had
			// its turn, then give it back.
			<-release
			r.Destroy()
		}(msgs[n])
	}

	var admitted, refused int

	for n := 0; n < flood; n++ {
		got := <-outcomes

		switch {
		case got.admitted:
			admitted++
		case errors.Is(got.err, ErrProtectedMemory) && errors.Is(got.err, enclave.ErrBudgetExhausted):
			refused++
		default:
			t.Errorf("ReadMessage1 under a constrained budget: got %v, want nil or ErrProtectedMemory", got.err)
		}
	}

	// Measured while the flood is still held: exactly the budget is in use, and
	// not one byte more.
	if got := allocator.InUse(); got != capacity*scheduleCost {
		t.Errorf("at the height of the flood, %d locked bytes are in use, want %d",
			got, capacity*scheduleCost)
	}

	close(release)
	wg.Wait()

	if admitted != capacity {
		t.Errorf("admitted %d connections, want exactly %d (the budget holds no more)", admitted, capacity)
	}
	if refused != wantRefus {
		t.Errorf("refused %d connections, want exactly %d", refused, wantRefus)
	}
	// Every responder was destroyed once the flood was released, so the budget
	// is whole again: a refusal costs nothing and an admission gives back what
	// it took.
	if got := allocator.InUse(); got != 0 {
		t.Errorf("after the flood, %d locked bytes are still in use", got)
	}
}

// A forged tag is the attacker's cheapest way to force an allocation: a
// structurally valid message 1 reaches the key schedule before its tag is
// checked. The rejection must give the bytes back, or a flood of forged tags
// accumulates reservations and exhausts the budget without ever authenticating.
func TestResponder_ForgedTagReturnsItsLockedBytes(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	i, forged := message1(t, static)
	defer i.Destroy()
	forged[len(forged)-1] ^= 0x01 // flip a tag bit

	iGenuine, genuine := message1(t, static)
	defer iGenuine.Destroy()

	allocator := withBudget(t, scheduleCost)

	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer r.Destroy()

	if err := r.ReadMessage1(forged); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ReadMessage1 with a forged tag: got %v, want ErrAuthentication", err)
	}
	if got := allocator.InUse(); got != 0 {
		t.Fatalf("a rejected forged-tag handshake kept %d locked bytes, want 0", got)
	}

	// The whole budget is free again, so a genuine handshake is admitted. If the
	// forged-tag path had kept its reservation, this would be refused.
	rGenuine := admitResponder(t, static, genuine)
	defer rGenuine.Destroy()
}

// Structural rejections happen before any allocation, so they must neither lock
// pages nor consult the budget even when it is exhausted -- and they must keep
// reporting their own error rather than an exhaustion error.
func TestResponder_StructuralRejectionsNeitherLockNorCharge(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	iHolder, holder := message1(t, static)
	defer iHolder.Destroy()

	allocator := withBudget(t, scheduleCost)

	// Hold the whole budget with an in-flight handshake.
	r := admitResponder(t, static, holder)
	defer r.Destroy()

	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		{"empty", nil, ErrMessageSize},
		{"truncated", make([]byte, Message1Size-1), ErrMessageSize},
		{"bad version", func() []byte {
			m := make([]byte, Message1Size)
			m[0] = 0xff
			m[1] = SuiteP256AESGCM
			return m
		}(), ErrUnsupportedVersion},
		{"bad suite", func() []byte {
			m := make([]byte, Message1Size)
			m[0] = Version
			m[1] = 0xff
			return m
		}(), ErrUnsupportedSuite},
		{"public key not on the curve", func() []byte {
			m := make([]byte, Message1Size)
			m[0] = Version
			m[1] = SuiteP256AESGCM
			m[2] = 0x04
			return m
		}(), ErrInvalidPublicKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := NewResponder(static)
			if err != nil {
				t.Fatalf("NewResponder: %v", err)
			}
			defer rr.Destroy()

			// Even with the budget full, a structural rejection is reported as
			// its own error, not ErrProtectedMemory -- it never allocates.
			if err := rr.ReadMessage1(tt.msg); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage1: got %v, want %v", err, tt.want)
			}
			if errors.Is(err, ErrProtectedMemory) {
				t.Fatalf("a structural rejection reported a locked-memory failure: %v", err)
			}
			assertNoSchedule(t, rr.sym, "a structurally rejected responder")
		})
	}

	if got := allocator.InUse(); got != scheduleCost {
		t.Fatalf("structural rejections changed the bytes in use to %d, want %d", got, scheduleCost)
	}
}

// NewResponder must not so much as reach the allocator: a bare connection that
// sends nothing has to cost nothing at all.
func TestNewResponder_TouchesNoBudget(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	reached := false
	prev := processAllocator
	processAllocator = func() (*enclave.Allocator, error) {
		reached = true
		return prev()
	}
	t.Cleanup(func() { processAllocator = prev })

	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer r.Destroy()

	if reached {
		t.Fatal("NewResponder reached the process allocator; a bare connection must cost nothing")
	}
	assertNoSchedule(t, r.sym, "a freshly constructed responder")
}

// An initiator's schedule is allocated eagerly, and that allocation can be
// refused like any other. It must fail rather than panic, and it must leave
// nothing behind.
func TestNewInitiator_ReportsAnExhaustedBudget(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	pub := static.PublicBytes()

	// A budget smaller than one schedule: the initiator's eager allocation is
	// refused outright.
	allocator := withBudget(t, scheduleCost-1)

	i, err := NewInitiator(pub)
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("NewInitiator under an exhausted budget: got %v, want ErrProtectedMemory", err)
	}
	if i != nil {
		t.Fatalf("NewInitiator returned a handshake alongside its error")
	}
	if got := allocator.InUse(); got != 0 {
		t.Fatalf("a half-allocated schedule leaked %d locked bytes", got)
	}
}

// GenerateStaticKey, NewStaticKey and DecodeStaticKey all draw locked pages, and
// all of them must report a refusal rather than ending the process.
func TestKeyConstructors_ReportAnExhaustedBudget(t *testing.T) {
	source, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer source.Destroy()

	scalar := sizedEnclave(t, PrivateKeySize)
	defer scalar.Destroy()
	encoded := sizedEnclave(t, HexKeySize)
	defer encoded.Destroy()
	if err := EncodeStaticKey(encoded, source); err != nil {
		t.Fatalf("EncodeStaticKey: %v", err)
	}

	// Zero capacity: every allocation is refused.
	allocator := withBudget(t, 1)

	tests := []struct {
		name string
		call func() error
	}{
		{"GenerateStaticKey", func() error { _, err := GenerateStaticKey(); return err }},
		{"NewStaticKey", func() error { _, err := NewStaticKey(scalar); return err }},
		{"DecodeStaticKey", func() error { _, err := DecodeStaticKey(encoded); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
				t.Fatalf("%s under an exhausted budget: got %v, want ErrProtectedMemory", tt.name, err)
			}
		})
	}

	if got := allocator.InUse(); got != 0 {
		t.Fatalf("refused key construction leaked %d locked bytes", got)
	}
}

// borrow classifies the two ways it can fail differently: an error the callback
// produced is passed through with its own classification, and an error the
// enclave produced is reported as ErrProtectedMemory.
func TestBorrow_ClassifiesTheCallersErrorSeparatelyFromTheEnclaves(t *testing.T) {
	t.Run("nil enclave", func(t *testing.T) {
		err := borrow("op", nil, func([]byte) error { return nil })
		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("got %v, want ErrProtectedMemory", err)
		}
	})

	t.Run("destroyed enclave", func(t *testing.T) {
		e := sizedEnclave(t, hashSize)
		e.Destroy()

		called := false
		err := borrow("op", e, func([]byte) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("got %v, want ErrProtectedMemory wrapping enclave.ErrEnclaveDestroyed", err)
		}
		if called {
			t.Fatal("the callback ran against a destroyed enclave")
		}
	})

	t.Run("the callback's own error passes through unchanged", func(t *testing.T) {
		e := sizedEnclave(t, hashSize)
		defer e.Destroy()

		want := failure("op", ErrKeyAgreement, "detail")
		err := borrow("op", e, func([]byte) error { return want })
		if !errors.Is(err, want) || err.Error() != want.Error() {
			t.Fatalf("got %v, want the callback's own error %v", err, want)
		}
		// Unchanged means UNWRAPPED as well as reachable: a borrow that rewrapped
		// it would still satisfy errors.Is above, and would reclassify it here.
		if errors.Is(err, ErrProtectedMemory) {
			t.Fatal("the callback's error was reclassified as a locked-memory failure")
		}
	})

	t.Run("success", func(t *testing.T) {
		e := sizedEnclave(t, hashSize)
		defer e.Destroy()

		if err := borrow("op", e, func(b []byte) error {
			if len(b) != hashSize {
				t.Errorf("borrowed %d bytes, want %d", len(b), hashSize)
			}
			return nil
		}); err != nil {
			t.Fatalf("borrow: %v", err)
		}
	})
}

// freeze reports a refusal rather than leaving the caller to assume the pages
// went read-only, and a destroyed enclave is the reachable refusal.
func TestFreeze_ReportsARefusal(t *testing.T) {
	e := sizedEnclave(t, hashSize)
	e.Destroy()

	err := freeze("op", e)
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("got %v, want ErrProtectedMemory wrapping enclave.ErrEnclaveDestroyed", err)
	}
}

// lockedBuffer reports a failure to reach the process allocator at all, which
// happens when the host's locked-memory ceiling cannot be read.
func TestLockedBuffer_ReportsAnUnreachableAllocator(t *testing.T) {
	sentinel := errors.New("discovery failed")

	prev := processAllocator
	processAllocator = func() (*enclave.Allocator, error) { return nil, sentinel }
	t.Cleanup(func() { processAllocator = prev })

	_, err := lockedBuffer("op", hashSize)
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want ErrProtectedMemory wrapping the discovery failure", err)
	}
}

// This package is Layer 0 and must never reach across the process: sizing the
// one locked-memory budget belongs to the binary, and destroying every enclave
// in the process belongs to the binary's shutdown. A library doing either is
// deciding for subsystems it knows nothing about (owner ruling 2026-09-22 on
// #19). That is a rule about the SOURCE, not about behaviour, so it is checked
// against the source: no behavioural test can prove an absence.
func TestPackage_NeverReachesAcrossTheProcess(t *testing.T) {
	const forbidden = "enclave.SetAllocator, enclave.WipeAll"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	fset := token.NewFileSet()

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "enclave" {
				return true
			}
			if sel.Sel.Name == "SetAllocator" || sel.Sel.Name == "WipeAll" {
				t.Errorf("%s calls enclave.%s; a Layer 0 library must not (%s are the binary's)",
					name, sel.Sel.Name, forbidden)
			}
			return true
		})
	}
}

// sizedEnclave allocates n bytes of writable locked memory for a test's own
// inputs. It deliberately bypasses the allocator seam: a test's fixtures must
// not consume the budget the test is squeezing.
func sizedEnclave(t *testing.T, n int) *enclave.MemoryEnclave {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveSized(n)
	if err != nil {
		t.Fatalf("enclave.NewMemoryEnclaveSized(%d): %v", n, err)
	}

	return e
}

// enclaveHolds reports whether e holds exactly want, comparing in constant time
// UNDER the enclave's read lock -- so the material is never copied into
// ordinary heap memory for a test to look at.
//
// It uses EqualToErr rather than EqualTo because EqualTo answers false for a
// destroyed enclave as well as for a mismatch, which would let an assertion
// like "these two keys differ" pass for a buffer that was released instead of
// for one that holds different bytes. A released enclave fails the test here.
func enclaveHolds(t *testing.T, e *enclave.MemoryEnclave, want []byte) bool {
	t.Helper()

	same, err := e.EqualToErr(want)
	if err != nil {
		t.Fatalf("comparing protected memory: %v", err)
	}

	return same
}

// assertEnclaveHolds fails unless e holds exactly want.
func assertEnclaveHolds(t *testing.T, e *enclave.MemoryEnclave, want []byte, context string) {
	t.Helper()

	if !enclaveHolds(t, e, want) {
		t.Errorf("%s: the protected buffer does not hold the expected value", context)
	}
}

// enclavesHoldTheSame compares two enclaves without either one leaving its
// locked region: the first is borrowed, and the second is compared against that
// borrowed view in constant time.
func enclavesHoldTheSame(t *testing.T, a, b *enclave.MemoryEnclave) bool {
	t.Helper()

	var same bool

	if err := a.WithBytes(func(view []byte) error {
		var cmpErr error
		same, cmpErr = b.EqualToErr(view)

		return cmpErr
	}); err != nil {
		t.Fatalf("comparing protected memory: %v", err)
	}

	return same
}

// mustSymmetricState builds an initiator-shaped key schedule for a test.
func mustSymmetricState(t *testing.T) *symmetricState {
	t.Helper()

	s, err := newSymmetricState("test")
	if err != nil {
		t.Fatalf("newSymmetricState: %v", err)
	}

	return s
}

// split is the one place this package takes TWO reservations in a row, so it is
// the one place a request can be half-satisfied: the first directional
// transport key is admitted and the second is refused. That leaves a live
// enclave nothing will ever return unless split releases it on the way out, and
// the budget it holds is capacity denied to every other connection for the rest
// of the process's life.
//
// The exhaustion tests elsewhere cannot reach it. They size the budget so that
// the FIRST request is refused, which never allocates anything, so deleting
// split's cleanup leaves them all green. These two aim at the boundary
// deliberately -- one page of headroom, exactly enough for the first key and
// not the second -- and drive it through the public API on both sides, because
// what a caller must be able to rely on is WriteMessage2 and ReadMessage2
// failing closed, not an internal helper doing so.

func TestResponder_APartiallyAllocatedSplitFailsClosedAndReleasesBoth(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	// Built before the budget is constrained, so the initiator's own schedule
	// is charged elsewhere and the arithmetic below is exactly the responder's.
	initiator, msg := message1(t, static)
	defer initiator.Destroy()

	// One page for the responder's schedule and one for the FIRST transport
	// key. The second has nowhere to go.
	allocator := withBudget(t, scheduleCost+transportKeyCost)

	r := admitResponder(t, static, msg)
	defer r.Destroy()

	if got := allocator.InUse(); got != scheduleCost {
		t.Fatalf("before the split, %d locked bytes are in use, want %d", got, scheduleCost)
	}

	reply, transport, err := r.WriteMessage2()

	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("WriteMessage2 with room for one transport key: got %v, want ErrProtectedMemory", err)
	}
	if reply != nil {
		t.Errorf("WriteMessage2 returned a reply alongside its error")
	}
	if transport != nil {
		t.Errorf("WriteMessage2 returned a transport alongside its error")
	}

	// The whole budget came back: the schedule from the terminal failure, and
	// the one transport key split had already taken when the second was
	// refused. Without split's release path this reads one page and stays
	// there for the process's lifetime.
	if got := allocator.InUse(); got != 0 {
		t.Errorf("a half-allocated split leaked %d locked bytes", got)
	}
	assertScheduleReleased(t, r.sym, "a responder whose split was refused")

	// And the handshake is spent rather than retryable: the transcript has
	// already absorbed an ephemeral that the peer will never see.
	if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("WriteMessage2 after a refused split: got %v, want ErrHandshakeState", err)
	}
}

func TestInitiator_APartiallyAllocatedSplitFailsClosedAndReleasesBoth(t *testing.T) {
	// One allocator for the whole test, generous while the exchange is set up
	// and then tightened around the initiator's split. Tightening mid-flight is
	// also the honest shape: a process budget does not grow for a connection
	// that is already open, it is consumed by every other connection on it.
	allocator := withBudget(t, 16*scheduleCost)

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	initiator, msg := message1(t, static)
	defer initiator.Destroy()

	r := admitResponder(t, static, msg)
	defer r.Destroy()

	reply, _, err := r.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}

	// The responder is finished and has given its schedule back, so what is
	// left is the static key and the initiator's own schedule. Leave room for
	// exactly one of the two transport keys ReadMessage2 is about to derive.
	held := allocator.InUse()
	if err := allocator.SetLimit(held + transportKeyCost); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}

	transport, err := initiator.ReadMessage2(reply)

	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("ReadMessage2 with room for one transport key: got %v, want ErrProtectedMemory", err)
	}
	if transport != nil {
		t.Errorf("ReadMessage2 returned a transport alongside its error")
	}

	// Back to the static key alone: the initiator's schedule was released by
	// the terminal failure and the half-allocated transport key by split.
	if got, want := allocator.InUse(), held-scheduleCost; got != want {
		t.Errorf("after a half-allocated split, %d locked bytes are in use, want %d", got, want)
	}
	assertScheduleReleased(t, initiator.sym, "an initiator whose split was refused")

	if _, err := initiator.ReadMessage2(reply); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("ReadMessage2 after a refused split: got %v, want ErrHandshakeState", err)
	}
}

// An enclave can be destroyed out from under a handshake that is still using
// it. The realistic cause is a binary's shutdown sweep -- enclave.WipeAll
// destroys every enclave in the process, and it belongs to the binary, so this
// library neither calls it nor can stop it -- but any owner of an enclave may
// Destroy one at any time.
//
// The contract #19 asks for is that such a destruction fails THAT connection
// with a typed error and touches nothing else: no panic, no damage to the
// handler, and no damage to the handshakes running beside it. That is the
// property memguard could not offer from the other direction either -- its
// exhaustion path destroyed every protected buffer in the process, so one
// connection's bad luck took every other connection's keys with it.
//
// Each case below destroys a live handshake's schedule and then makes the call
// that needs it. The error is ErrProtectedMemory carrying
// enclave.ErrEnclaveDestroyed, exactly as an exhausted budget carries
// enclave.ErrBudgetExhausted, so one classification serves a caller for every
// way protected memory can be unavailable.
func TestHandshake_SurvivesItsProtectedMemoryBeingDestroyed(t *testing.T) {
	// Named explicitly rather than left to the runtime: "returns an error
	// instead of panicking" is the requirement, so a panic must fail with a
	// message that says which requirement broke.
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("destroying a live handshake's protected memory panicked: %v", p)
		}
	}()

	t.Run("a responder between message 1 and message 2", func(t *testing.T) {
		allocator := withBudget(t, 16*scheduleCost)

		static, err := GenerateStaticKey()
		if err != nil {
			t.Fatalf("GenerateStaticKey: %v", err)
		}
		defer static.Destroy()

		initiator, msg := message1(t, static)
		defer initiator.Destroy()

		victim := admitResponder(t, static, msg)
		defer victim.Destroy()

		held := allocator.InUse()

		victim.sym.schedule.Destroy()

		reply, transport, err := victim.WriteMessage2()
		assertDestroyedMemoryFailure(t, err, "WriteMessage2")

		if reply != nil {
			t.Errorf("WriteMessage2 returned a reply alongside its error")
		}
		if transport != nil {
			t.Errorf("WriteMessage2 returned a transport alongside its error")
		}
		if _, _, err := victim.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage2 after the failure: got %v, want ErrHandshakeState", err)
		}

		// The destroyed enclave gave its reservation back, so the budget the
		// dead connection held is available to the next one rather than
		// stranded for the life of the process.
		if got, want := allocator.InUse(), held-scheduleCost; got != want {
			t.Errorf("after the destruction, %d locked bytes are in use, want %d", got, want)
		}

		assertHandshakesStillWork(t, static)
	})

	t.Run("an initiator before message 1", func(t *testing.T) {
		allocator := withBudget(t, 16*scheduleCost)

		static, err := GenerateStaticKey()
		if err != nil {
			t.Fatalf("GenerateStaticKey: %v", err)
		}
		defer static.Destroy()

		victim, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		defer victim.Destroy()

		held := allocator.InUse()

		victim.sym.schedule.Destroy()

		msg, err := victim.WriteMessage1()
		assertDestroyedMemoryFailure(t, err, "WriteMessage1")

		if msg != nil {
			t.Errorf("WriteMessage1 returned a message alongside its error")
		}
		if _, err := victim.WriteMessage1(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage1 after the failure: got %v, want ErrHandshakeState", err)
		}
		if got, want := allocator.InUse(), held-scheduleCost; got != want {
			t.Errorf("after the destruction, %d locked bytes are in use, want %d", got, want)
		}

		assertHandshakesStillWork(t, static)
	})

	t.Run("an initiator between message 1 and message 2", func(t *testing.T) {
		allocator := withBudget(t, 16*scheduleCost)

		static, err := GenerateStaticKey()
		if err != nil {
			t.Fatalf("GenerateStaticKey: %v", err)
		}
		defer static.Destroy()

		victim, msg := message1(t, static)
		defer victim.Destroy()

		responder := admitResponder(t, static, msg)
		defer responder.Destroy()

		reply, _, err := responder.WriteMessage2()
		if err != nil {
			t.Fatalf("WriteMessage2: %v", err)
		}

		held := allocator.InUse()

		victim.sym.schedule.Destroy()

		transport, err := victim.ReadMessage2(reply)
		assertDestroyedMemoryFailure(t, err, "ReadMessage2")

		if transport != nil {
			t.Errorf("ReadMessage2 returned a transport alongside its error")
		}
		if _, err := victim.ReadMessage2(reply); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("ReadMessage2 after the failure: got %v, want ErrHandshakeState", err)
		}
		if got, want := allocator.InUse(), held-scheduleCost; got != want {
			t.Errorf("after the destruction, %d locked bytes are in use, want %d", got, want)
		}

		assertHandshakesStillWork(t, static)
	})
}

// assertDestroyedMemoryFailure pins the classification a caller gets when the
// protected memory a handshake was using has been released underneath it.
func assertDestroyedMemoryFailure(t *testing.T, err error, op string) {
	t.Helper()

	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("%s on a destroyed schedule: got %v, want ErrProtectedMemory", op, err)
	}
	if !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("%s on a destroyed schedule: got %v, want enclave.ErrEnclaveDestroyed", op, err)
	}
	if errors.Is(err, ErrHandshakeState) {
		t.Errorf("%s reported a caller-ordering mistake for a protected-memory failure: %v", op, err)
	}
}

// assertHandshakesStillWork runs a complete, independent handshake and a
// transport round-trip. It is the "and nothing else broke" half of every case
// above: a failure that took the process, the static key, or the package's
// allocator accounting with it would fail here rather than pass quietly.
func assertHandshakesStillWork(t *testing.T, static *StaticKey) {
	t.Helper()

	initiator, msg := message1(t, static)
	defer initiator.Destroy()

	responder := admitResponder(t, static, msg)
	defer responder.Destroy()

	reply, responderTransport, err := responder.WriteMessage2()
	if err != nil {
		t.Fatalf("an unrelated handshake could not complete: %v", err)
	}

	initiatorTransport, err := initiator.ReadMessage2(reply)
	if err != nil {
		t.Fatalf("an unrelated initiator could not complete: %v", err)
	}

	ad := []byte("header")
	pt := []byte("payload")

	got, err := responderTransport.Open(sealOne(t, initiatorTransport, pt, ad), ad)
	if err != nil {
		t.Fatalf("an unrelated transport could not open its frame: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("an unrelated transport round-trip = %q, want %q", got, pt)
	}
}

// The static credential is the one piece of protected memory a responder does
// not allocate and does not own, and it is the one whose destruction is
// INVISIBLE to the rest of the handshake: crypto/ecdh keeps its own heap copy
// of the scalar for the key's lifetime, and that copy still answers ECDH after
// the enclave holding the authoritative scalar has been wiped.
//
// So a responder built while the key was alive would, without a guard at the
// point of use, go on authenticating peers out of a heap copy of a credential
// the process had already destroyed -- completing handshakes on released
// credentials instead of failing that one connection. NewResponder's alive()
// check cannot catch it: it answers for the moment it was read, and the sweep
// happens afterwards.
func TestResponder_RefusesAStaticCredentialWipedAfterConstruction(t *testing.T) {
	allocator := withBudget(t, 16*scheduleCost)

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	// A second, untouched credential for the bystander check. It has to be a
	// different key: the wiped one cannot authenticate anything afterwards, by
	// design, so reusing it would test the wrong thing.
	bystanderStatic, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer bystanderStatic.Destroy()

	initiator, msg := message1(t, static)
	defer initiator.Destroy()

	// Constructed while the credential is alive, so alive() passes here and
	// this responder is past the only check that used to exist.
	victim, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer victim.Destroy()

	// A shutdown sweep destroys the enclave without going through
	// StaticKey.Destroy, which is precisely why the heap copy survives it.
	static.scalar.Destroy()

	if static.priv == nil {
		t.Fatal("crypto/ecdh's private key was cleared by the sweep; this test no longer reproduces the hazard it guards")
	}
	if static.alive() {
		t.Fatal("the static key reports itself alive after its enclave was destroyed")
	}

	held := allocator.InUse()

	err = victim.ReadMessage1(msg)
	assertDestroyedMemoryFailure(t, err, "ReadMessage1")

	// Terminal, so a retry cannot walk back into the ECDH.
	if err := victim.ReadMessage1(msg); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("ReadMessage1 after the failure: got %v, want ErrHandshakeState", err)
	}

	// ReadMessage1 allocates the key schedule BEFORE it reaches the key
	// agreement, so the refused connection has a reservation to give back.
	if got := allocator.InUse(); got != held {
		t.Errorf("the refused connection leaked %d locked bytes", got-held)
	}
	assertScheduleReleased(t, victim.sym, "a responder whose static credential was wiped")

	// A responder holding a live credential is untouched.
	assertHandshakesStillWork(t, bystanderStatic)
}

// withScalar's own refusals, including the defensive branch no public path can
// reach -- a key whose enclave is alive but whose crypto/ecdh half is not.
func TestStaticKey_WithScalarRefusesAnUnusableCredential(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		var key *StaticKey

		err := key.withScalar("op", func(*ecdh.PrivateKey) error {
			t.Error("fn ran for a nil static key")
			return nil
		})
		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("got %v, want ErrProtectedMemory", err)
		}
	})

	t.Run("destroyed key", func(t *testing.T) {
		key, err := GenerateStaticKey()
		if err != nil {
			t.Fatalf("GenerateStaticKey: %v", err)
		}
		key.Destroy()

		err = key.withScalar("op", func(*ecdh.PrivateKey) error {
			t.Error("fn ran for a destroyed static key")
			return nil
		})
		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("got %v, want ErrProtectedMemory", err)
		}
	})

	t.Run("a live enclave with no private half", func(t *testing.T) {
		// Unreachable through the public API -- every constructor sets both --
		// so it is built directly. It is the branch that stops a nil
		// dereference if a future change ever separates the two.
		key := &StaticKey{scalar: sizedEnclave(t, PrivateKeySize)}
		defer key.scalar.Destroy()

		err := key.withScalar("op", func(*ecdh.PrivateKey) error {
			t.Error("fn ran without a private key")
			return nil
		})
		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("got %v, want ErrProtectedMemory", err)
		}
		if errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("a live enclave was reported as destroyed: %v", err)
		}
	})

	t.Run("the callback's own error passes through", func(t *testing.T) {
		key, err := GenerateStaticKey()
		if err != nil {
			t.Fatalf("GenerateStaticKey: %v", err)
		}
		defer key.Destroy()

		want := failure("op", ErrKeyAgreement, "detail")

		got := key.withScalar("op", func(priv *ecdh.PrivateKey) error {
			if priv == nil {
				t.Error("fn received a nil private key for a live credential")
			}
			return want
		})
		if !errors.Is(got, want) || got.Error() != want.Error() {
			t.Fatalf("got %v, want the callback's own error %v", got, want)
		}
		if errors.Is(got, ErrProtectedMemory) {
			t.Error("the callback's error was reclassified as a protected-memory failure")
		}
	})
}
