package dns

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ErrTsigSessionInvalid is returned when an operation is attempted on a TSIG
// session that has been invalidated. An invalidated session must not be
// reused; create a new one with NewTsigSession.
var ErrTsigSessionInvalid error = &Error{err: "tsig session invalid"}

// ErrTsigSessionNoPending is returned by TsigSession.Confirm when there is no
// prepared message waiting to be confirmed.
var ErrTsigSessionNoPending error = &Error{err: "no prepared message to confirm"}

// TsigSessionState is a snapshot of a TsigSession's state. It is safe to log
// or include in reports: it never contains the shared secret nor any MAC.
type TsigSessionState struct {
	// Sent is the number of messages whose sending was confirmed.
	Sent int
	// Verified is the number of incoming messages that verified successfully.
	Verified int
	// Pending reports whether a message was prepared but not yet confirmed.
	Pending bool
	// Valid reports whether the session may still be used.
	Valid bool
}

// String returns a human-readable summary of the session state. It contains
// no secret key material and no MACs.
func (s TsigSessionState) String() string {
	return fmt.Sprintf("tsig session: sent=%d verified=%d pending=%t valid=%t",
		s.Sent, s.Verified, s.Pending, s.Valid)
}

// TsigSession provides explicit, stateful TSIG signing and verification for a
// sequence of consecutively signed messages exchanged over a single
// connection, as described in RFC 8945, Section 5.2.2 (and RFC 2845,
// Section 4.4). Every message in the session is signed, and the MAC of each
// confirmed message is used as the request MAC when signing or verifying the
// next message, forming a chain.
//
// The key material is only ever obtained from the in-process TsigProvider
// given to NewTsigSession; the session itself never sees or stores it.
//
// Session states:
//
//   - fresh: no message has been confirmed yet. The first message is signed
//     and verified without a request MAC and with the full TSIG variables
//     included in the MAC calculation.
//   - prepared: Prepare has signed a message, but the outcome of sending it
//     is not yet known. The chain is only advanced once Confirm is called.
//   - confirmed: the prepared message was sent successfully; its MAC becomes
//     the request MAC for the next message.
//   - invalid: after Invalidate (e.g. when the send result of a prepared
//     message is uncertain) the session must not be reused; create a new one.
//
// Verification never advances the state on failure: a message that does not
// verify leaves the chain untouched, so a subsequent, correctly chained
// message still verifies.
//
// A TsigSession is not safe for concurrent use.
type TsigSession struct {
	provider TsigProvider
	now      func() uint64 // injected clock, returns seconds since the epoch

	lastMAC string // MAC of the last confirmed/verified message, hex encoded
	pending string // MAC of a prepared but not yet confirmed message

	sent     int
	verified int
	valid    bool
}

// NewTsigSession returns a new TsigSession that signs and verifies messages
// using provider. The clock function is used for the TimeSigned field of
// outgoing messages and for the time-fudge check of incoming ones; if clock
// is nil, the system clock is used.
func NewTsigSession(provider TsigProvider, clock func() uint64) *TsigSession {
	if clock == nil {
		clock = func() uint64 { return uint64(time.Now().Unix()) }
	}
	return &TsigSession{provider: provider, now: clock, valid: true}
}

// Prepare signs m and returns it in wire format, chaining on the MAC of the
// last confirmed or verified message. The message must carry a stub TSIG RR
// as the last record in the additional section (see SetTsig); if its
// TimeSigned is zero it is set from the session's clock.
//
// Prepare does not advance the chain: the session only starts using the new
// MAC after Confirm is called. If the send result of the returned message is
// uncertain, call Invalidate and do not reuse the session.
func (s *TsigSession) Prepare(m *Msg) ([]byte, error) {
	if !s.valid {
		return nil, ErrTsigSessionInvalid
	}
	rr := m.IsTsig()
	if rr == nil {
		return nil, ErrNoSig
	}
	if rr.TimeSigned == 0 {
		rr.TimeSigned = s.now()
	}
	// The first message of a session is signed without a request MAC and
	// with the full TSIG variables; subsequent messages chain on the
	// previous MAC and cover the timers only (RFC 8945, 5.2.2).
	out, mac, err := TsigGenerateWithProvider(m, s.provider, s.lastMAC, s.lastMAC != "")
	if err != nil {
		return nil, err
	}
	s.pending = mac
	return out, nil
}

// Confirm marks the message signed by the last Prepare call as successfully
// sent and advances the chain to its MAC. It returns ErrTsigSessionNoPending
// if there is no prepared message waiting for confirmation.
func (s *TsigSession) Confirm() error {
	if !s.valid {
		return ErrTsigSessionInvalid
	}
	if s.pending == "" {
		return ErrTsigSessionNoPending
	}
	s.lastMAC = s.pending
	s.pending = ""
	s.sent++
	return nil
}

// Invalidate marks the session as unusable, e.g. because the send result of
// a prepared message is uncertain. All further operations on the session
// fail with ErrTsigSessionInvalid and the session must not be reused.
func (s *TsigSession) Invalidate() {
	s.valid = false
	s.pending = ""
	s.lastMAC = ""
}

// Verify verifies the TSIG of the wire-format message msg, chaining on the
// MAC of the last confirmed or verified message. The message ID in the DNS
// header is checked against the TSIG's OrigId, and TimeSigned is checked
// against the session's clock within the fudge factor, following the real
// TSIG rules (RFC 8945, Section 5.2).
//
// On success the chain is advanced to the MAC of msg. On failure the session
// state is left untouched, so a later, correctly chained message can still
// verify.
func (s *TsigSession) Verify(msg []byte) error {
	if !s.valid {
		return ErrTsigSessionInvalid
	}

	// Work on a copy: stripTsig adjusts the ARCOUNT in place, and a failed
	// verification must not have side effects on the caller's buffer.
	msg = append(make([]byte, 0, len(msg)), msg...)

	// Strip the TSIG from the incoming msg.
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return err
	}

	// The message ID in the header must match the original ID in the TSIG.
	if id := binary.BigEndian.Uint16(msg[0:2]); id != tsig.OrigId {
		return ErrId
	}

	buf, err := tsigBuffer(stripped, tsig, s.lastMAC, s.lastMAC != "")
	if err != nil {
		return err
	}

	if err := s.provider.Verify(buf, tsig); err != nil {
		return err
	}

	// Fudge factor works both ways. A message can arrive before it was
	// signed because of clock skew. Checked after the signature, following
	// draft-ietf-dnsop-rfc2845bis (CVE-2017-3142/3143).
	now := s.now()
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < ti {
		return ErrTime
	}

	// Only now that the message is fully verified, advance the chain.
	s.lastMAC = tsig.MAC
	s.verified++
	return nil
}

// State returns a snapshot of the session state. The snapshot contains no
// secret key material and no MACs, so it is safe to log or report.
func (s *TsigSession) State() TsigSessionState {
	return TsigSessionState{
		Sent:     s.sent,
		Verified: s.verified,
		Pending:  s.pending != "",
		Valid:    s.valid,
	}
}
