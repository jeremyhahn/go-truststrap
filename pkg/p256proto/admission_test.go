// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"errors"
	"testing"
)

// These tests exercise the responder admission cap that closes the measured
// connect-cost denial of service (#17, Codex review 918). They mutate the
// package-global cap, so they must not run in parallel with anything; each
// restores the prior cap and asserts the live-schedule count returns to zero,
// which also serves as a package-wide leak detector for the admission slot.

// withCap sets the responder admission cap for one test and restores it after,
// asserting no admission slot was leaked.
func withCap(t *testing.T, n int) {
	t.Helper()

	if live := liveResponders.Load(); live != 0 {
		t.Fatalf("a previous test leaked %d admission slot(s); the cap accounting is unsound", live)
	}

	prev := MaxConcurrentResponders()
	SetMaxConcurrentResponders(n)
	t.Cleanup(func() {
		SetMaxConcurrentResponders(prev)
		if live := liveResponders.Load(); live != 0 {
			t.Errorf("this test leaked %d admission slot(s)", live)
		}
	})
}

// admittedResponder runs a matched initiator and responder up to a successful
// ReadMessage1, so the responder is authenticated and holds an admission slot
// but has not yet run WriteMessage2. The caller finishes it or destroys it.
func admittedResponder(t *testing.T, static *StaticKey) (*Initiator, *Responder) {
	t.Helper()

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if err := r.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}

	return i, r
}

// The core property: once the cap is reached, a further responder fails closed
// with a typed error, locks nothing, and does not disturb the handshakes that
// hold the slots -- they still complete and their transport still works.
func TestResponder_AdmissionCapFailsClosedWithoutDamagingActiveHandshakes(t *testing.T) {
	withCap(t, 2)

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// Fill the cap with two authenticated, in-flight handshakes.
	i1, r1 := admittedResponder(t, static)
	defer i1.Destroy()
	defer r1.Destroy()
	i2, r2 := admittedResponder(t, static)
	defer i2.Destroy()
	defer r2.Destroy()

	if live := liveResponders.Load(); live != 2 {
		t.Fatalf("live responder schedules = %d, want 2", live)
	}

	// A third responder is refused: the cap is full. It must lock nothing, take
	// no slot, and report the typed error rather than panicking.
	iExtra, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	defer iExtra.Destroy()
	msgExtra, err := iExtra.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}

	rExtra, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer rExtra.Destroy()

	overCapErr := rExtra.ReadMessage1(msgExtra)
	if !errors.Is(overCapErr, ErrResourceExhausted) {
		t.Fatalf("ReadMessage1 over the cap: got %v, want ErrResourceExhausted", overCapErr)
	}
	// The rendered message names the operation and the limit, without repeating
	// the classification (the sentinel prefix is dropped exactly once).
	if got, want := overCapErr.Error(), "p256proto: ReadMessage1: too many concurrent responder handshakes: limit 2"; got != want {
		t.Errorf("error message = %q, want %q", got, want)
	}
	assertNoSchedule(t, rExtra.sym, "a responder denied admission")
	if live := liveResponders.Load(); live != 2 {
		t.Fatalf("a denied admission changed the live count to %d, want 2", live)
	}

	// The two in-flight handshakes are undamaged: both complete and their
	// transports round-trip. This is the "no damage to active handshakes" half
	// of the finding.
	for n, pair := range []struct {
		i *Initiator
		r *Responder
	}{{i1, r1}, {i2, r2}} {
		msg2, responder, err := pair.r.WriteMessage2()
		if err != nil {
			t.Fatalf("handshake %d WriteMessage2: %v", n, err)
		}
		initiator, err := pair.i.ReadMessage2(msg2)
		if err != nil {
			t.Fatalf("handshake %d ReadMessage2: %v", n, err)
		}

		ad := []byte("header")
		pt := []byte("payload")
		got, err := responder.Open(sealOne(t, initiator, pt, ad), ad)
		if err != nil {
			t.Fatalf("handshake %d transport Open: %v", n, err)
		}
		if string(got) != string(pt) {
			t.Fatalf("handshake %d transport round-trip = %q, want %q", n, got, pt)
		}
	}

	// Completing them released their slots, so capacity is available again.
	if live := liveResponders.Load(); live != 0 {
		t.Fatalf("live responder schedules after completion = %d, want 0", live)
	}
	i3, r3 := admittedResponder(t, static)
	defer i3.Destroy()
	defer r3.Destroy()
}

// A forged tag is the attacker's cheapest way to force an allocation: a
// structurally valid message 1 reaches the key schedule before its tag is
// checked. The rejection must release the slot, or a flood of forged tags
// accumulates slots and defeats the cap without ever authenticating.
func TestResponder_ForgedTagReleasesItsAdmissionSlot(t *testing.T) {
	withCap(t, 1)

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	forged := func() []byte {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		defer i.Destroy()
		msg, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		msg[len(msg)-1] ^= 0x01 // flip a tag bit
		return msg
	}

	r1, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer r1.Destroy()
	if err := r1.ReadMessage1(forged()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ReadMessage1 with a forged tag: got %v, want ErrAuthentication", err)
	}
	if live := liveResponders.Load(); live != 0 {
		t.Fatalf("a rejected forged-tag handshake leaked its slot: live = %d, want 0", live)
	}

	// The single slot is free again, so a genuine handshake is admitted. If the
	// forged-tag path had leaked its slot, this would be refused at cap 1.
	i2, r2 := admittedResponder(t, static)
	defer i2.Destroy()
	defer r2.Destroy()
}

// Structural rejections happen before any allocation or admission, so they must
// neither lock pages nor consume a slot even when the cap is exhausted.
func TestResponder_StructuralRejectionsNeitherLockNorAdmit(t *testing.T) {
	withCap(t, 1)

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// Hold the only slot with an in-flight handshake.
	i, r := admittedResponder(t, static)
	defer i.Destroy()
	defer r.Destroy()

	tests := []struct {
		name string
		msg  []byte
		want error
	}{
		{"empty", nil, ErrMessageSize},
		{"truncated", make([]byte, Message1Size-1), ErrMessageSize},
		{"bad version", func() []byte { m := make([]byte, Message1Size); m[0] = 0xff; m[1] = SuiteP256AESGCM; return m }(), ErrUnsupportedVersion},
		{"bad suite", func() []byte { m := make([]byte, Message1Size); m[0] = Version; m[1] = 0xff; return m }(), ErrUnsupportedSuite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := NewResponder(static)
			if err != nil {
				t.Fatalf("NewResponder: %v", err)
			}
			defer rr.Destroy()

			// Even with the cap full, a structural rejection is reported as its
			// own error, not ErrResourceExhausted -- it never reaches admission.
			if err := rr.ReadMessage1(tt.msg); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage1: got %v, want %v", err, tt.want)
			}
			assertNoSchedule(t, rr.sym, "a structurally rejected responder")
		})
	}

	if live := liveResponders.Load(); live != 1 {
		t.Fatalf("structural rejections changed the live count to %d, want 1", live)
	}
}

func TestSetMaxConcurrentResponders_ClampsToAtLeastOne(t *testing.T) {
	prev := MaxConcurrentResponders()
	t.Cleanup(func() { SetMaxConcurrentResponders(prev) })

	for _, n := range []int{0, -1, -100} {
		SetMaxConcurrentResponders(n)
		if got := MaxConcurrentResponders(); got != 1 {
			t.Errorf("SetMaxConcurrentResponders(%d): cap = %d, want 1", n, got)
		}
	}

	SetMaxConcurrentResponders(64)
	if got := MaxConcurrentResponders(); got != 64 {
		t.Errorf("cap = %d, want 64", got)
	}
}

func TestResponderCap_StartingCapIsDerivedFromRLIMIT(t *testing.T) {
	// init derives the cap from this process's RLIMIT_MEMLOCK, and every other
	// test restores the cap it found, so outside a test body the live cap equals
	// defaultResponderLimit(). This pins that the derived default is actually
	// wired into init rather than left at the zero value (which
	// SetMaxConcurrentResponders would clamp to 1) or the raw constant. The
	// derivation LOGIC is proved independently by TestDeriveResponderCap; this
	// only proves the wiring and that the result is in range.
	want := defaultResponderLimit()
	if got := MaxConcurrentResponders(); got != want {
		t.Fatalf("starting cap = %d, want the derived default %d", got, want)
	}
	if want < minResponderLimit || want > DefaultMaxConcurrentResponders {
		t.Fatalf("derived default %d out of range [%d,%d]", want, minResponderLimit, DefaultMaxConcurrentResponders)
	}
}

// deriveResponderCap is the security-critical arithmetic: the ceiling must fall
// out of RLIMIT_MEMLOCK, not a fixed count. Every expectation here is computed
// by hand (one quarter of the limit, divided by the per-schedule footprint,
// clamped to [1, 256]) so it is independent of the constants under test -- a
// mutation of the divisor, the clamp, or the floor turns a row red.
func TestDeriveResponderCap(t *testing.T) {
	// A fixed footprint so the arithmetic is host-page-size independent; the
	// real footprint is lockedBytesPerSchedule() on the running host.
	const perSchedule = int64(4 * 4096) // 16384 bytes

	tests := []struct {
		name        string
		memlock     uint64
		perSchedule int64
		want        int
	}{
		// No RLIMIT to derive from: the hygiene default stands.
		{"unlimited falls back to the hygiene default", unlimitedMemlock, perSchedule, DefaultMaxConcurrentResponders},
		// The classic 64 KiB unprivileged default: (65536/4)/16384 = 1. This is
		// the deployment a fixed 256 could not protect (Codex 945).
		{"classic 64 KiB unprivileged default admits one", 64 * 1024, perSchedule, 1},
		// (1048576/4)/16384 = 16.
		{"one mebibyte derives sixteen", 1 << 20, perSchedule, 16},
		// (16777216/4)/16384 = 256, exactly the clamp boundary.
		{"sixteen mebibytes reaches the clamp boundary", 16 << 20, perSchedule, 256},
		// (67108864/4)/16384 = 1024, clamped down to 256.
		{"a large limit is clamped to the maximum default", 64 << 20, perSchedule, DefaultMaxConcurrentResponders},
		// (16384/4)/16384 = 0, floored to one rather than refusing every peer.
		{"a budget below one schedule floors to one", 16 * 1024, perSchedule, minResponderLimit},
		{"a zero limit floors to one", 0, perSchedule, minResponderLimit},
		// A caller mistake, not a runtime condition: fall back rather than divide by zero.
		{"a non-positive footprint falls back to the default", 1 << 20, 0, DefaultMaxConcurrentResponders},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveResponderCap(tt.memlock, tt.perSchedule); got != tt.want {
				t.Errorf("deriveResponderCap(%d, %d) = %d, want %d", tt.memlock, tt.perSchedule, got, tt.want)
			}
		})
	}
}

// A constrained limit must derive a cap STRICTLY BELOW the old fixed default:
// the whole point of the change is that 256 was unsafe on a low-memlock box.
func TestDeriveResponderCap_ConstrainedLimitIsBelowTheFixedDefault(t *testing.T) {
	const perSchedule = int64(4 * 4096)
	if got := deriveResponderCap(64*1024, perSchedule); got >= DefaultMaxConcurrentResponders {
		t.Fatalf("a 64 KiB limit derived %d, want below the old fixed default %d", got, DefaultMaxConcurrentResponders)
	}
}
