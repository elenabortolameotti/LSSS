package crypto

import "errors"

type PartialSignature struct {
	Index ParticipantID
	Z     Scalar
}

type Signature struct {
	R Point
	Z Scalar
}

type WirePartialSignature struct {
	Index []byte
	Z     []byte
}

type WireSignature struct {
	R []byte
	Z []byte
}

type ReconstructionSet struct {
	Indices []ParticipantID
	Shares  []Scalar
}

// Nonce
type NonceShare struct {
	Index ParticipantID
	ri    Scalar
	Ri    []byte
	ci    []byte
}

func (n *NonceShare) SetRi() error {
	var ki *Scalar
	err := generateRandomScalar(ki)
	if err != nil {
		return err
	}
	var Ri *Point
	Ri = Ri.ScalarBaseMult(ki)
	n.Ri = Ri.Bytes()
	return nil
}

func (n *NonceShare) GetRi() ([]byte, error) {
	if n.Ri == nil {
		return nil, errors.New("n.GetRi failed: Ri is not set")
	}
	out := make([]byte, len(n.Ri))
	copy(out, n.Ri)
	return out, nil
}

func (n *NonceShare) SetCommit	(sess *Session) error {

func (n *NonceShare) GetCommit() []byte {
	out := make([]byte, len(n.ci))
	copy(out, n.ci)
	return out
}

// Session
type Session struct {
	ID        []byte
	Indices   []ParticipantID
	IndexHash []byte
}

// Participant
type ParticipantSigner struct {
	p Participant
	P Point
	R Point
	z Scalar
	n NonceShare
}

func (ps *ParticipantSigner) SetParticipant(p Participant) {
	ps.p = p
}

func (ps *ParticipantSigner) GetParticipant() Participant {
	return ps.p
}

func (ps *ParticipantSigner) GetP() Point {
	return ps.P
}

func (ps *ParticipantSigner) SetP(P Point) {
	ps.P = P
}

func (ps *ParticipantSigner) SetR(r [][]byte, ids []ParticipantID) error {
	var R Point
	for _, rBytes := range r {
		var Ri *Point
		Ri, err := Ri.SetBytes(rBytes)
		if err != nil {
			return err
		}
		R.Add(&R, Ri)
	}
	ps.R = R
	return nil
}

func (ps *ParticipantSigner) GetR() Point {
	return ps.R
}

func (ps *ParticipantSigner) SetN(n NonceShare) {
	ps.n = n
}

func (ps *ParticipantSigner) GetN() NonceShare {
	return ps.n
}

// Server
type ServerSigner struct {
	s Server
	P Point
	R Point
	z Scalar
	n NonceShare
}

func (ss *ServerSigner) SetParticipant(s Server) {
	ss.s = s
}

func (ss *ServerSigner) GetParticipant() Server {
	return ss.s
}

func (ss *ServerSigner) GetS() Point {
	return ss.P
}

func (ss *ServerSigner) SetP(P Point) {
	ss.P = P
}

func (ps *ParticipantSigner) SetR(r [][]byte) error {
	var R Point
	for _, rBytes := range r {
		var Ri *Point
		Ri, err := Ri.SetBytes(rBytes)
		if err != nil {
			return err
		}
		R.Add(&R, Ri)
	}
	ps.R = R
	return nil
}

func (ps *ParticipantSigner) GetR() Point {
	return ps.R
}

func (ps *ParticipantSigner) SetN(n NonceShare) {
	ps.n = n
}

func (ps *ParticipantSigner) GetN() NonceShare {
	return ps.n
}
