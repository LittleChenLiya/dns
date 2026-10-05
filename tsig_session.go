package dns

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// TsigClock is an injectable source of time used by TsigSession when signing
// and verifying TSIG records. It exists so that tests (and applications that
// need deterministic time handling) can control the time that is stamped into
// the TimeSigned field and used for the fudge check.
type TsigClock interface {
	// Now returns the current time.
	Now() time.Time
}

// TsigClockFunc is an adapter that allows a function to be used as a
// TsigClock. If f is a function with the appropriate signature,
// TsigClockFunc(f) is a TsigClock that calls f.
type TsigClockFunc func() time.Time

// Now calls f.
func (f TsigClockFunc) Now() time.Time { return f() }

// tsigSessionState is the state of a TsigSession.
type tsigSessionState uint8

const (
	// tsigSessionOpen is the normal state: the session can prepare, confirm
	// and verify messages.
	tsigSessionOpen tsigSessionState = iota
	// tsigSessionInvalid is the state after an unrecoverable error (such as a
	// send whose outcome is unknown). A session in this state can no longer be
	// used; a new session must be created.
	tsigSessionInvalid
)

// TsigRole determines which TSIG message type a session expects to receive.
// The role is fixed for the lifetime of a session and drives the OrigId check
// applied to received messages (RFC 8945 section 5.3).
type TsigRole uint8

const (
	// TsigInitiator is the role of the party that sends the first request.
	// An initiator session signs requests and verifies the corresponding
	// responses; received messages are checked as responses, i.e. their
	// OrigId must match the ID of the last request that was sent.
	TsigInitiator TsigRole = iota
	// TsigResponder is the role of the party that receives the first request.
	// A responder session verifies requests and signs responses; received
	// messages are checked as requests, i.e. their OrigId must match the
	// message header ID.
	TsigResponder
)

// String returns the name of the role.
func (r TsigRole) String() string {
	switch r {
	case TsigInitiator:
		return "initiator"
	case TsigResponder:
		return "responder"
	default:
		return fmt.Sprintf("TsigRole(%d)", uint8(r))
	}
}

// String returns the name of the state.
func (s tsigSessionState) String() string {
	switch s {
	case tsigSessionOpen:
		return "open"
	case tsigSessionInvalid:
		return "invalid"
	default:
		return fmt.Sprintf("tsigSessionState(%d)", uint8(s))
	}
}

// TsigSession is an explicit, stateful TSIG security association between two
// peers. It handles a sequence of messages that are each individually signed,
// chaining them together: the MAC of the last confirmed message is used as the
// request MAC of the next one (RFC 8945 section 6, TSIG on TCP connections).
//
// A session is created with NewTsigSession and is used in one of two ways
// depending on its role:
//
//   - The initiator calls Prepare to sign a request, sends the returned bytes,
//     and calls Confirm once the send is known to have succeeded. If the send
//     fails or its outcome is uncertain (for example a timeout), Invalidate
//     must be called and the session must not be reused.
//   - The responder calls Verify on each request it receives. If verification
//     fails the session state is unchanged and the previous MAC remains in
//     force; a correctly chained retry can still be verified.
//
// The session never holds the secret itself; all cryptographic operations are
// performed by the TsigProvider it was created with. The String method does not
// reveal the secret or any MAC value.
type TsigSession struct {
	mu       sync.Mutex
	provider TsigProvider
	clock    TsigClock
	role     TsigRole
	state    tsigSessionState
	keyName  string // key name of the first message; enforced for all messages
	lastMAC  string // hex-encoded MAC of the last confirmed message ("" before the first)
	lastID   uint16 // header ID of the last message sent (initiator: for response OrigId check)
}

// TsigPending is a prepared but not yet confirmed send. It is returned by
// Prepare and must be passed to Confirm once the send is known to have
// succeeded, or discarded (and the session invalidated) if the send fails or
// its outcome is uncertain.
type TsigPending struct {
	session *TsigSession
	mac     string // MAC of the prepared message, not yet committed
	id      uint16 // header ID of the prepared message
}

// NewTsigSession creates a new TSIG session. The provider is used for all
// cryptographic operations (the session never sees the secret); the clock is
// used for TSIG time checks (if nil, the system clock is used); the role
// determines the OrigId check applied to received messages.
func NewTsigSession(provider TsigProvider, role TsigRole, clock TsigClock) *TsigSession {
	if provider == nil {
		panic("dns: nil TsigProvider")
	}
	if clock == nil {
		clock = TsigClockFunc(time.Now)
	}
	return &TsigSession{
		provider: provider,
		clock:    clock,
		role:     role,
	}
}

// Prepare signs m and returns the wire bytes to send. The returned TsigPending
// must be passed to Confirm once the send is known to have succeeded; until then
// the session state (the last confirmed MAC) is unchanged. If the send fails or
// its outcome is uncertain, Invalidate must be called and the session must not
// be reused.
func (s *TsigSession) Prepare(m *Msg) ([]byte, *TsigPending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != tsigSessionOpen {
		return nil, nil, ErrTsigSessionInvalid
	}
	if m.IsTsig() == nil {
		return nil, nil, ErrNoSig
	}
	rr := m.IsTsig()
	if s.keyName != "" && s.keyName != rr.Hdr.Name {
		return nil, nil, ErrKey
	}
	now := uint64(s.clock.Now().Unix())
	rr.TimeSigned = 0 // force tsigBuffer to stamp the injected clock
	out, mac, err := tsigGenerate(m, s.provider, s.lastMAC, false, now)
	if err != nil {
		return nil, nil, err
	}
	if s.keyName == "" {
		s.keyName = rr.Hdr.Name
	}
	return out, &TsigPending{session: s, mac: mac, id: m.Id}, nil
}

// Confirm commits a prepared send, advancing the session's last confirmed MAC
// to the MAC of that message. It must be called once the send is known to have
// succeeded. If the send fails or its outcome is uncertain, Invalidate must be
// called instead and the session must not be reused.
func (s *TsigSession) Confirm(p *TsigPending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != tsigSessionOpen {
		return ErrTsigSessionInvalid
	}
	if p == nil || p.session != s {
		return ErrTsigSessionPending
	}
	s.lastMAC = p.mac
	s.lastID = p.id
	p.session = nil
	return nil
}

// Invalidate marks the session as no longer usable. It must be called when a
// send fails or its outcome is uncertain (for example a timeout), because the
// message may or may not have been processed by the peer and the last confirmed
// MAC can no longer be trusted. After Invalidate the session cannot be reused;
// a new session must be created.
func (s *TsigSession) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = tsigSessionInvalid
}

// Verify verifies a received message and, on success, advances the session's
// last confirmed MAC to the MAC of that message. On failure the session state
// is unchanged, so a correctly chained retry can still be verified. The OrigId
// check follows RFC 8945 section 5.3: requests must have OrigId equal to the
// message header ID; responses must have OrigId equal to the ID of the request
// that was sent.
func (s *TsigSession) Verify(msg []byte) (*TSIG, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != tsigSessionOpen {
		return nil, ErrTsigSessionInvalid
	}
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return nil, err
	}
	// OrigId check per RFC 8945 section 5.3.
	hdrID := binary.BigEndian.Uint16(msg[0:2])
	if s.role == TsigResponder {
		// Request: OrigId MUST equal the message header ID.
		if tsig.OrigId != hdrID {
			return nil, ErrTsigSessionID
		}
	} else {
		// Response: OrigId MUST equal the ID of the request we sent.
		if s.lastMAC == "" {
			return nil, ErrTsigSessionID
		}
		if tsig.OrigId != s.lastID {
			return nil, ErrTsigSessionID
		}
	}
	if s.keyName != "" && s.keyName != tsig.Hdr.Name {
		return nil, ErrKey
	}
	now := uint64(s.clock.Now().Unix())
	buf, err := tsigBuffer(stripped, tsig, s.lastMAC, false, now)
	if err != nil {
		return nil, err
	}
	if err := s.provider.Verify(buf, tsig); err != nil {
		return nil, err
	}
	// Time check (same logic as tsigVerify).
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < ti {
		return nil, ErrTime
	}
	// Verification succeeded: advance the chain.
	s.lastMAC = tsig.MAC
	if s.keyName == "" {
		s.keyName = tsig.Hdr.Name
	}
	return tsig, nil
}

// String returns a description of the session. It never reveals the secret or
// any MAC value.
func (s *TsigSession) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("TsigSession{role=%s, state=%s, key=%q}", s.role, s.state, s.keyName)
}
