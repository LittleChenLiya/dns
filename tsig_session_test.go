package dns

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// sessionSecret is the base64 secret used by the session tests.
const sessionSecret = "pRZgBrBvI4NAHZYhxmhs/Q=="

// sessionClock is an injectable clock returning a fixed time, so the tests are
// deterministic.
var sessionClock = TsigClockFunc(func() time.Time { return time.Unix(int64(timeSigned), 0) })

func sessionProvider() TsigProvider {
	return tsigSecretProvider{"example.": sessionSecret}
}

// newSessionMsg returns a signed test message with the given id. Both the
// message header ID and the TSIG OrigId are set to the same value so the
// request/response OrigId checks pass.
func newSessionMsg(id uint16) *Msg {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.SetTsig("example.", HmacSHA256, 300, time.Now().Unix())
	m.Id = id
	m.IsTsig().OrigId = id
	return m
}

// TestTsigSessionChain verifies that two messages, each individually signed and
// chained with the previous confirmed MAC, verify in sequence.
func TestTsigSessionChain(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	responder := NewTsigSession(sessionProvider(), TsigResponder, sessionClock)

	// Message 1: initiator -> responder.
	m1 := newSessionMsg(1)
	out1, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator.Confirm(p1); err != nil {
		t.Fatal(err)
	}
	tsig1, err := responder.Verify(out1)
	if err != nil {
		t.Fatalf("message 1: %v", err)
	}
	if tsig1.MAC == "" {
		t.Fatal("expected a non-empty MAC")
	}
	if responder.lastMAC == "" {
		t.Fatal("responder lastMAC was not advanced after message 1")
	}
	if responder.lastMAC != tsig1.MAC {
		t.Fatal("responder lastMAC does not match the verified MAC")
	}

	// Message 2: initiator -> responder, chained with the MAC of message 1.
	m2 := newSessionMsg(2)
	out2, p2, err := initiator.Prepare(m2)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator.Confirm(p2); err != nil {
		t.Fatal(err)
	}
	tsig2, err := responder.Verify(out2)
	if err != nil {
		t.Fatalf("message 2: %v", err)
	}
	if responder.lastMAC != tsig2.MAC {
		t.Fatal("responder lastMAC does not match the verified MAC of message 2")
	}

	// The two MACs must differ (each message is individually signed).
	if tsig1.MAC == tsig2.MAC {
		t.Fatal("expected distinct MACs for distinct messages")
	}
}

// TestTsigSessionBadSignatureKeepsState verifies that a message with a bad
// signature does not advance the session state: the previous confirmed MAC
// remains in force and a correctly chained retry can still be verified.
func TestTsigSessionBadSignatureKeepsState(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	responder := NewTsigSession(sessionProvider(), TsigResponder, sessionClock)

	// Message 1 verifies and advances the state.
	m1 := newSessionMsg(1)
	out1, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	initiator.Confirm(p1)
	if _, err := responder.Verify(out1); err != nil {
		t.Fatal(err)
	}
	lastMAC := responder.lastMAC

	// Message 2 is signed correctly (chained with MAC of message 1) but the
	// MAC in the wire is corrupted.
	m2 := newSessionMsg(2)
	out2, _, err := initiator.Prepare(m2)
	if err != nil {
		t.Fatal(err)
	}
	var m2unpacked Msg
	if err := m2unpacked.Unpack(out2); err != nil {
		t.Fatal(err)
	}
	tsig2 := m2unpacked.IsTsig()
	macBytes, err := hex.DecodeString(tsig2.MAC)
	if err != nil {
		t.Fatal(err)
	}
	macBytes[0] ^= 0xff // corrupt the MAC
	tsig2.MAC = hex.EncodeToString(macBytes)
	out2bad, err := m2unpacked.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Verify(out2bad); err != ErrSig {
		t.Fatalf("expected ErrSig, got %v", err)
	}
	if responder.lastMAC != lastMAC {
		t.Fatal("state advanced after a bad signature")
	}

	// A correctly chained message 2 (same chaining, uncorrupted) still verifies.
	if _, err := responder.Verify(out2); err != nil {
		t.Fatalf("correctly chained retry should verify: %v", err)
	}
	if responder.lastMAC == lastMAC {
		t.Fatal("state was not advanced after a valid retry")
	}
}

// TestTsigSessionIDMismatch verifies that the OrigId check follows the real
// TSIG rules: requests must have OrigId equal to the message header ID, and
// responses must have OrigId equal to the ID of the request that was sent.
func TestTsigSessionIDMismatch(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	responder := NewTsigSession(sessionProvider(), TsigResponder, sessionClock)

	// Initiator sends request 1.
	m1 := newSessionMsg(1)
	out1, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	initiator.Confirm(p1)

	// Responder receives the request with a tampered OrigId (mismatch with the
	// message header ID).
	var req Msg
	if err := req.Unpack(out1); err != nil {
		t.Fatal(err)
	}
	reqTsig := req.IsTsig()
	reqTsig.OrigId = 999
	outReqBad, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Verify(outReqBad); err != ErrTsigSessionID {
		t.Fatalf("expected ErrTsigSessionID for request, got %v", err)
	}

	// Initiator receives a response whose OrigId does not match the request ID.
	var resp Msg
	if err := resp.Unpack(out1); err != nil {
		t.Fatal(err)
	}
	respTsig := resp.IsTsig()
	respTsig.OrigId = 888
	outRespBad, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Verify(outRespBad); err != ErrTsigSessionID {
		t.Fatalf("expected ErrTsigSessionID for response, got %v", err)
	}

	// A valid response (OrigId == request ID, correctly chained) passes both the
	// ID check and the signature check. The responder must have verified request
	// 1 to have the correct last MAC for chaining.
	responder2 := NewTsigSession(sessionProvider(), TsigResponder, sessionClock)
	if _, err := responder2.Verify(out1); err != nil {
		t.Fatal(err)
	}
	respMsg := new(Msg)
	respMsg.SetReply(m1)
	respMsg.SetTsig("example.", HmacSHA256, 300, time.Now().Unix())
	respMsg.Id = m1.Id
	respMsg.IsTsig().OrigId = m1.Id
	outResp, pResp, err := responder2.Prepare(respMsg)
	if err != nil {
		t.Fatal(err)
	}
	responder2.Confirm(pResp)
	if _, err := initiator.Verify(outResp); err != nil {
		t.Fatalf("valid response should verify: %v", err)
	}
}

// TestTsigSessionSendFailure verifies that after a send failure (or any send
// whose outcome is uncertain) the session is invalidated and cannot be reused;
// a new session must be created.
func TestTsigSessionSendFailure(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)

	m1 := newSessionMsg(1)
	_, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a send failure: invalidate the session.
	initiator.Invalidate()
	if err := initiator.Confirm(p1); err != ErrTsigSessionInvalid {
		t.Fatalf("expected ErrTsigSessionInvalid, got %v", err)
	}
	// Further use of the session fails.
	m2 := newSessionMsg(2)
	if _, _, err := initiator.Prepare(m2); err != ErrTsigSessionInvalid {
		t.Fatalf("expected ErrTsigSessionInvalid, got %v", err)
	}
	if _, err := initiator.Verify([]byte{}); err != ErrTsigSessionInvalid {
		t.Fatalf("expected ErrTsigSessionInvalid, got %v", err)
	}
	// A new session is required.
	initiator2 := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	out2, p2, err := initiator2.Prepare(m2)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator2.Confirm(p2); err != nil {
		t.Fatal(err)
	}
	_ = out2
}

// TestTsigSessionPendingNotConfirmed verifies that Confirm only accepts a
// pending send that was prepared by the same session.
func TestTsigSessionPendingNotConfirmed(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	other := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)

	m1 := newSessionMsg(1)
	_, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	// Confirming a pending send from another session fails.
	if err := other.Confirm(p1); err != ErrTsigSessionPending {
		t.Fatalf("expected ErrTsigSessionPending, got %v", err)
	}
	// Confirming twice fails.
	if err := initiator.Confirm(p1); err != nil {
		t.Fatal(err)
	}
	if err := initiator.Confirm(p1); err != ErrTsigSessionPending {
		t.Fatalf("expected ErrTsigSessionPending on double confirm, got %v", err)
	}
}

// TestTsigSessionClock verifies that the injected clock is used: a message
// signed with one clock and verified with a clock far in the future fails with
// ErrTime.
func TestTsigSessionClock(t *testing.T) {
	past := TsigClockFunc(func() time.Time { return time.Unix(int64(timeSigned), 0) })
	future := TsigClockFunc(func() time.Time { return time.Unix(int64(timeSigned)+1000, 0) })

	initiator := NewTsigSession(sessionProvider(), TsigInitiator, past)
	responder := NewTsigSession(sessionProvider(), TsigResponder, future)

	m1 := newSessionMsg(1)
	out1, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	initiator.Confirm(p1)
	if _, err := responder.Verify(out1); err != ErrTime {
		t.Fatalf("expected ErrTime, got %v", err)
	}
}

// TestTsigSessionString verifies that String does not reveal the secret or any
// MAC value.
func TestTsigSessionString(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	s := initiator.String()
	if strings.Contains(s, sessionSecret) {
		t.Fatal("String() leaks the secret")
	}

	m1 := newSessionMsg(1)
	_, p1, err := initiator.Prepare(m1)
	if err != nil {
		t.Fatal(err)
	}
	initiator.Confirm(p1)
	s = initiator.String()
	if strings.Contains(s, p1.mac) {
		t.Fatal("String() leaks the MAC")
	}
}

// TestTsigSessionConcurrent verifies that concurrent use of a session is safe.
func TestTsigSessionConcurrent(t *testing.T) {
	initiator := NewTsigSession(sessionProvider(), TsigInitiator, sessionClock)
	responder := NewTsigSession(sessionProvider(), TsigResponder, sessionClock)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 20; i++ {
			m := newSessionMsg(uint16(i + 1))
			out, p, err := initiator.Prepare(m)
			if err != nil {
				t.Error(err)
				return
			}
			if err := initiator.Confirm(p); err != nil {
				t.Error(err)
				return
			}
			if _, err := responder.Verify(out); err != nil {
				t.Error(err)
				return
			}
		}
		close(done)
	}()
	for i := 0; i < 20; i++ {
		initiator.String()
		responder.String()
	}
	<-done
}

// TestTsigSecretProvider exercises the in-memory TsigProvider (the
// tsigSecretProvider map) directly: correct key, unknown key name and bad
// signature.
func TestTsigSecretProvider(t *testing.T) {
	provider := tsigSecretProvider{"example.": sessionSecret}
	tsig := TSIG{
		Hdr:       RR_Header{Name: "example.", Rrtype: TypeTSIG, Class: ClassANY},
		Algorithm: HmacSHA256,
	}
	msg := []byte("the quick brown fox")

	mac, err := provider.Generate(msg, &tsig)
	if err != nil {
		t.Fatal(err)
	}
	tsig.MAC = hex.EncodeToString(mac)
	if err := provider.Verify(msg, &tsig); err != nil {
		t.Fatal(err)
	}

	// Unknown key name -> ErrSecret.
	tsigBad := tsig
	tsigBad.Hdr.Name = "other."
	if _, err := provider.Generate(msg, &tsigBad); err != ErrSecret {
		t.Fatalf("expected ErrSecret, got %v", err)
	}
	if err := provider.Verify(msg, &tsigBad); err != ErrSecret {
		t.Fatalf("expected ErrSecret, got %v", err)
	}

	// Bad signature -> ErrSig.
	tsigBadSig := tsig
	tsigBadSig.MAC = "00"
	if err := provider.Verify(msg, &tsigBadSig); err != ErrSig {
		t.Fatalf("expected ErrSig, got %v", err)
	}

	// Nil provider -> panic.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil provider")
		}
	}()
	NewTsigSession(nil, TsigInitiator, sessionClock)
}
