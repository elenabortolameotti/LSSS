package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Session
type Session struct {
	id        []byte
	indices   []ParticipantID
	indexHash []byte
}

func (s *Session) HasParticipant(id ParticipantID) bool {
	for _, x := range s.indices {
		if x == id {
			return true
		}
	}
	return false
}

func (s *Session) SetID(id []byte) error {
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		return err
	}
	s.id = sid
	return nil
}

func (s *Session) GetID() []byte {
	return s.id
}

func (s *Session) SetIndices(indices []ParticipantID) {
	s.indices = indices
}

func (s *Session) GetIndices() []ParticipantID {
	out := make([]ParticipantID, len(s.indices))
	copy(out, s.indices)
	return out
}

func (s *Session) SetIndexHash(ids []byte) {
	h := sha256.New()
	tmp := make([]byte, 4)

	for _, id := range ids {
		binary.BigEndian.PutUint32(tmp, uint32(id))
		h.Write(tmp)
	}
	s.indexHash = h.Sum(nil)
}

func (s *Session) GetIndexHash() []byte {
	return s.indexHash
}

func (s *Session) GetNumParticipants() int {
	return len(s.indices)
}

type WirePartialSignature struct {
	Index []byte
	Z     []byte
}

type WireSignature struct {
	R []byte
	Z []byte
}

// Nonce
type NonceShare struct {
	index  ParticipantID
	ri     Scalar
	set_ri bool
	Ri     []byte
	ci     []byte
}

func (n *NonceShare) SetIndex(index ParticipantID) error {
	if index < 0 {
		return errors.New("n.SetIndex failed: index must be non-negative")
	}
	n.index = index
	return nil
}

func (n *NonceShare) GetIndex() ParticipantID {
	return n.index
}

func (n *NonceShare) Setri() error {
	err := generateRandomScalar(&n.ri)
	if err != nil {
		return err
	}
	n.set_ri = true
	return nil
}

func (n *NonceShare) Getri() Scalar {
	return n.ri
}

func (n *NonceShare) SetRi() error {
	if !n.set_ri {
		return errors.New("n.SetRi failed: ri is not set")
	}
	var Ri *Point
	Ri = Ri.ScalarBaseMult(&n.ri)
	n.Ri = Ri.Bytes()
	return nil
}

func (n *NonceShare) GetRi() ([]byte, error) {
	if n.Ri == nil {
		return nil, errors.New("n.GetRi failed: Ri is not set")
	}
	return n.Ri, nil
}

func (n *NonceShare) SetCommit(sess *Session) {
	n.ci = commitNonce(sess, n.index, n.Ri)
}

func (n *NonceShare) GetCommit() ([]byte, error) {
	if n.ci == nil {
		return nil, errors.New("n.GetCommit failed: ci is not set")
	}
	return n.ci, nil
}

// Material to send to others at first
type MaterialToSend1 struct {
	Index    ParticipantID
	setIndex bool
	ci       []byte
	setci    bool
}

func (m *MaterialToSend1) SetIndex(index ParticipantID) {
	m.Index = index
	m.setIndex = true
}

func (m *MaterialToSend1) GetIndex() ParticipantID {
	return m.Index
}

func (m *MaterialToSend1) SetCommit(ci []byte) {
	m.ci = ci
	m.setci = true
}

func (m *MaterialToSend1) GetCommit() []byte {
	return m.ci
}

// Participant
type ParticipantSigner struct {
	p               Participant
	P               Point
	R               Point
	n               NonceShare
	sess            Session
	partialSig      WirePartialSignature
	finalSig        WireSignature
	materialToSend1 MaterialToSend1 // material to send to others at first
}

func (ps *ParticipantSigner) SetParticipant(p Participant) {
	ps.p = p
}

func (ps *ParticipantSigner) GetParticipant() Participant {
	return ps.p
}

func (ps *ParticipantSigner) SetP(P Point) {
	ps.P = P
}

func (ps *ParticipantSigner) GetP() Point {
	return ps.P
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

func (ps *ParticipantSigner) SetMaterialToSend1(m MaterialToSend1) {
	ps.materialToSend1 = m
}

func (ps *ParticipantSigner) GetMaterialToSend1() MaterialToSend1 {
	return ps.materialToSend1
}

func (ps *ParticipantSigner) SetPartialSignature(msg []byte) error {

	var zero Scalar

	share := ps.p.GetShare()
	lambda := ps.p.GetLagrangeCoefficient()

	ri := ps.n.Getri()

	if share.Equal(&zero) == 1 {
		return errors.New("missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ps.sess, ps.R, ps.P, msg)
	if err != nil {
		return err
	}

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ps.partialSig = WirePartialSignature{
		Index: IntToBytes(int(ps.p.GetID())),
		Z:     z.Bytes(),
	}

	return nil
}

func (ps *ParticipantSigner) GetPartialSignature() WirePartialSignature {
	return ps.partialSig
}

func (ps *ParticipantSigner) VerifyNonce(mat *MaterialToSend1, Ri []byte) (bool, error) { // Verify the material received from another participant
	boolean, err := VerifyNonceAux(&ps.sess, mat.Index, mat.ci, Ri)
	if err != nil {
		return false, fmt.Errorf("VerifyNonceAux failed: %w", err)
	}
	return boolean, nil
}

// Server
type ServerSigner struct {
	s               Server
	P               Point
	R               Point
	n               NonceShare
	sess            Session
	partialSig      WirePartialSignature
	finalSig        WireSignature
	materialToSend1 MaterialToSend1 // material to send to others at first
}

func (ss *ServerSigner) SetParticipant(s Server) {
	ss.s = s
}

func (ss *ServerSigner) GetParticipant() Server {
	return ss.s
}

func (ss *ServerSigner) SetP(P Point) {
	ss.P = P
}

func (ss *ServerSigner) GetS() Point {
	return ss.P
}

func (ss *ServerSigner) SetR(r [][]byte) error {
	var R Point
	for _, rBytes := range r {
		var Ri *Point
		Ri, err := Ri.SetBytes(rBytes)
		if err != nil {
			return err
		}
		R.Add(&R, Ri)
	}
	ss.R = R
	return nil
}

func (ss *ServerSigner) GetR() Point {
	return ss.R
}

func (ss *ServerSigner) SetN(n NonceShare) {
	ss.n = n
}

func (ss *ServerSigner) GetN() NonceShare {
	return ss.n
}

func (ss *ServerSigner) SetPartialSignature(msg []byte) error {

	var zero Scalar

	share := ss.s.GetShare()
	lambda := ss.s.GetLagrangeCoefficient()

	ri := ss.n.Getri()

	if share.Equal(&zero) == 1 {
		return errors.New("missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ss.sess, ss.R, ss.P, msg)
	if err != nil {
		return err
	}

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ss.partialSig = WirePartialSignature{
		Index: IntToBytes(int(ServerID)),
		Z:     z.Bytes(),
	}

	return nil
}

func (ss *ServerSigner) GetPartialSignature() WirePartialSignature {
	return ss.partialSig
}

func (ss *ServerSigner) VerifyNonce(mat *MaterialToSend1, Ri []byte) (bool, error) { // Verify the material received from another participant
	boolean, err := VerifyNonceAux(&ss.sess, mat.Index, mat.ci, Ri)
	if err != nil {
		return false, fmt.Errorf("VerifyNonceAux failed: %w", err)
	}
	return boolean, nil
}
