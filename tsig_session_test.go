package dns

import (
	"errors"
	"strings"
	"testing"
)

const (
	tsigSessionKeyName = "sessionkey."
	tsigSessionSecret  = "pRZgBrBvI4NAHZYhxmhs/Q=="
)

// fixedClock returns an injectable clock set to a fixed point in time.
func fixedClock(t uint64) func() uint64 {
	return func() uint64 { return t }
}

func newSessionMsg(id uint16) *Msg {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.Id = id
	m.SetTsig(tsigSessionKeyName, HmacSHA256, 300, 0)
	return m
}

func sessionProvider() TsigProvider {
	return tsigSecretProvider(map[string]string{tsigSessionKeyName: tsigSessionSecret})
}

// corruptMAC returns a copy of the wire message with the TSIG MAC altered.
func corruptMAC(t *testing.T, wire []byte) []byte {
	t.Helper()
	m := new(Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	tsig := m.IsTsig()
	if tsig == nil {
		t.Fatal("no TSIG in message")
	}
	// Flip the first hex pair of the MAC, keeping its length intact.
	if strings.HasPrefix(tsig.MAC, "00") {
		tsig.MAC = "01" + tsig.MAC[2:]
	} else {
		tsig.MAC = "00" + tsig.MAC[2:]
	}
	out, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTsigSecretProvider exercises the in-memory provider: signing and
// verifying with a known key works, an unknown key fails with ErrSecret.
func TestTsigSecretProvider(t *testing.T) {
	provider := sessionProvider()

	m := newSessionMsg(1)
	buf, mac, err := TsigGenerateWithProvider(m, provider, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if mac == "" {
		t.Fatal("expected a MAC")
	}
	if err := TsigVerifyWithProvider(buf, provider, "", false); err != nil {
		t.Fatal(err)
	}

	// Unknown key name must fail with ErrSecret on both paths.
	m = newSessionMsg(2)
	m.Extra[len(m.Extra)-1].(*TSIG).Hdr.Name = "nosuchkey."
	if _, _, err := TsigGenerateWithProvider(m, provider, "", false); !errors.Is(err, ErrSecret) {
		t.Fatalf("expected ErrSecret, got %v", err)
	}
	m = newSessionMsg(3)
	buf, _, err = TsigGenerateWithProvider(m, provider, "", false)
	if err != nil {
		t.Fatal(err)
	}
	m.Unpack(buf)
	m.IsTsig().Hdr.Name = "nosuchkey."
	buf, err = m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := TsigVerifyWithProvider(buf, provider, "", false); !errors.Is(err, ErrSecret) {
		t.Fatalf("expected ErrSecret, got %v", err)
	}
}

// TestTsigSessionVerifyChain signs two small messages in order and verifies
// them in order with a second session; both must pass.
func TestTsigSessionVerifyChain(t *testing.T) {
	const now = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(now))
	receiver := NewTsigSession(sessionProvider(), fixedClock(now))

	for i := uint16(1); i <= 2; i++ {
		wire, err := sender.Prepare(newSessionMsg(i))
		if err != nil {
			t.Fatalf("prepare message %d: %v", i, err)
		}
		if st := sender.State(); !st.Pending {
			t.Fatalf("message %d: expected pending state, got %v", i, st)
		}
		if err := sender.Confirm(); err != nil {
			t.Fatalf("confirm message %d: %v", i, err)
		}
		if err := receiver.Verify(wire); err != nil {
			t.Fatalf("verify message %d: %v", i, err)
		}
	}

	if st := sender.State(); st.Sent != 2 || !st.Valid {
		t.Fatalf("unexpected sender state: %v", st)
	}
	if st := receiver.State(); st.Verified != 2 || !st.Valid {
		t.Fatalf("unexpected receiver state: %v", st)
	}
}

// TestTsigSessionBadSignatureKeepsState verifies that a bad signature on the
// second message does not advance the receiver chain: the exchange of that
// message fails, the old state is kept, and a correctly chained second
// message still verifies afterwards.
func TestTsigSessionBadSignatureKeepsState(t *testing.T) {
	const now = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(now))
	receiver := NewTsigSession(sessionProvider(), fixedClock(now))

	wire1, err := sender.Prepare(newSessionMsg(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Confirm(); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Verify(wire1); err != nil {
		t.Fatal(err)
	}

	wire2, err := sender.Prepare(newSessionMsg(2))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Confirm(); err != nil {
		t.Fatal(err)
	}

	// The exchange of the corrupted second message must fail.
	bad := corruptMAC(t, wire2)
	if err := receiver.Verify(bad); !errors.Is(err, ErrSig) {
		t.Fatalf("expected ErrSig, got %v", err)
	}

	// The old state must be kept: still one verified message, chain not
	// advanced, so the genuine second message still verifies.
	if st := receiver.State(); st.Verified != 1 || !st.Valid {
		t.Fatalf("state advanced on bad signature: %v", st)
	}
	if err := receiver.Verify(wire2); err != nil {
		t.Fatalf("correctly chained message rejected after bad signature: %v", err)
	}
	if st := receiver.State(); st.Verified != 2 {
		t.Fatalf("unexpected receiver state: %v", st)
	}
}

// TestTsigSessionOrigIdMismatch checks that a message whose header ID does
// not match the TSIG OrigId is rejected with ErrId.
func TestTsigSessionOrigIdMismatch(t *testing.T) {
	const now = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(now))
	receiver := NewTsigSession(sessionProvider(), fixedClock(now))

	wire, err := sender.Prepare(newSessionMsg(7))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the header ID without touching the TSIG OrigId.
	wire[0], wire[1] = 0, 8
	if err := receiver.Verify(wire); !errors.Is(err, ErrId) {
		t.Fatalf("expected ErrId, got %v", err)
	}
	if st := receiver.State(); st.Verified != 0 {
		t.Fatalf("state advanced on ID mismatch: %v", st)
	}
}

// TestTsigSessionSendFailureInvalidates checks that when the send result of
// a prepared message is uncertain the session is invalidated and cannot be
// reused; a new session is required.
func TestTsigSessionSendFailureInvalidates(t *testing.T) {
	const now = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(now))

	if _, err := sender.Prepare(newSessionMsg(1)); err != nil {
		t.Fatal(err)
	}
	// The send result is uncertain: invalidate instead of confirming.
	sender.Invalidate()

	if st := sender.State(); st.Valid || st.Pending || st.Sent != 0 {
		t.Fatalf("unexpected state after invalidate: %v", st)
	}
	if _, err := sender.Prepare(newSessionMsg(1)); !errors.Is(err, ErrTsigSessionInvalid) {
		t.Fatalf("expected ErrTsigSessionInvalid from Prepare, got %v", err)
	}
	if err := sender.Confirm(); !errors.Is(err, ErrTsigSessionInvalid) {
		t.Fatalf("expected ErrTsigSessionInvalid from Confirm, got %v", err)
	}
	if err := sender.Verify([]byte{}); !errors.Is(err, ErrTsigSessionInvalid) {
		t.Fatalf("expected ErrTsigSessionInvalid from Verify, got %v", err)
	}

	// A new session is needed and works.
	fresh := NewTsigSession(sessionProvider(), fixedClock(now))
	wire, err := fresh.Prepare(newSessionMsg(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Confirm(); err != nil {
		t.Fatal(err)
	}
	receiver := NewTsigSession(sessionProvider(), fixedClock(now))
	if err := receiver.Verify(wire); err != nil {
		t.Fatal(err)
	}
}

// TestTsigSessionConfirmWithoutPending checks that Confirm without a
// prepared message fails.
func TestTsigSessionConfirmWithoutPending(t *testing.T) {
	s := NewTsigSession(sessionProvider(), fixedClock(1700000000))
	if err := s.Confirm(); !errors.Is(err, ErrTsigSessionNoPending) {
		t.Fatalf("expected ErrTsigSessionNoPending, got %v", err)
	}
}

// TestTsigSessionClockInjection checks that the injected clock governs both
// signing time and the fudge check: a message signed at t0 fails verification
// when the receiver clock is far ahead, and the state is not advanced.
func TestTsigSessionClockInjection(t *testing.T) {
	const t0 = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(t0))
	wire, err := sender.Prepare(newSessionMsg(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Confirm(); err != nil {
		t.Fatal(err)
	}

	// Receiver clock 400s ahead, fudge is 300s: must fail with ErrTime.
	receiver := NewTsigSession(sessionProvider(), fixedClock(t0+400))
	if err := receiver.Verify(wire); !errors.Is(err, ErrTime) {
		t.Fatalf("expected ErrTime, got %v", err)
	}
	if st := receiver.State(); st.Verified != 0 {
		t.Fatalf("state advanced on time error: %v", st)
	}

	// Within the fudge window it verifies.
	receiver = NewTsigSession(sessionProvider(), fixedClock(t0+299))
	if err := receiver.Verify(wire); err != nil {
		t.Fatal(err)
	}
}

// TestTsigSessionStateReportNoSecrets ensures the state report contains
// neither the secret nor any MAC material.
func TestTsigSessionStateReportNoSecrets(t *testing.T) {
	const now = 1700000000
	sender := NewTsigSession(sessionProvider(), fixedClock(now))
	wire, err := sender.Prepare(newSessionMsg(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Confirm(); err != nil {
		t.Fatal(err)
	}

	report := sender.State().String()
	if strings.Contains(report, tsigSessionSecret) {
		t.Fatalf("report leaks secret: %q", report)
	}
	// Extract the MAC of the sent message and make sure it is not reported.
	m := new(Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if mac := m.IsTsig().MAC; mac != "" && strings.Contains(report, mac) {
		t.Fatalf("report leaks MAC: %q", report)
	}
}
