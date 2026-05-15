package test

import (
	"testing"

	"github.com/elenabortolameotti/LSSS/crypto"
)

func logSection(t *testing.T, title string) {
	t.Helper()
	t.Logf("\n========== %s ==========", title)
}

func logOK(t *testing.T, msg string) {
	t.Helper()
	t.Logf("[OK] %s", msg)
}

func makeParticipantNonce(t *testing.T, ps *crypto.ParticipantSigner) crypto.NonceShare {
	t.Helper()

	var nonce crypto.NonceShare

	if err := nonce.SetIndex(ps.GetParticipant().GetID()); err != nil {
		t.Fatalf("failed to set participant nonce index: %v", err)
	}
	if err := nonce.Setri(); err != nil {
		t.Fatalf("failed to generate participant private nonce: %v", err)
	}
	if err := nonce.SetRi(); err != nil {
		t.Fatalf("failed to compute participant public nonce: %v", err)
	}

	sess := ps.GetSession()
	nonce.SetCommit(&sess)

	ps.SetN(nonce)

	return nonce
}

func makeServerNonce(t *testing.T, ss *crypto.ServerSigner) crypto.NonceShare {
	t.Helper()

	var nonce crypto.NonceShare

	if err := nonce.SetIndex(crypto.ServerID); err != nil {
		t.Fatalf("failed to set server nonce index: %v", err)
	}
	if err := nonce.Setri(); err != nil {
		t.Fatalf("failed to generate server private nonce: %v", err)
	}
	if err := nonce.SetRi(); err != nil {
		t.Fatalf("failed to compute server public nonce: %v", err)
	}

	sess := ss.GetSession()
	nonce.SetCommit(&sess)

	ss.SetNonce(nonce)

	return nonce
}

func makeMaterial1(t *testing.T, n crypto.NonceShare) crypto.MaterialToSend1 {
	t.Helper()

	ci, err := n.GetCommit()
	if err != nil {
		t.Fatalf("failed to get nonce commitment: %v", err)
	}

	var m crypto.MaterialToSend1
	m.SetIndex(n.GetIndex())
	m.SetCommit(ci)

	return m
}

func makeMaterial2(t *testing.T, n crypto.NonceShare) crypto.MaterialToSend2 {
	t.Helper()

	Ri, err := n.GetRi()
	if err != nil {
		t.Fatalf("failed to get public nonce Ri: %v", err)
	}

	var m crypto.MaterialToSend2
	m.SetIndex(n.GetIndex())
	m.SetRi(*Ri)

	return m
}

func checkShareConsistency(
	t *testing.T,
	name string,
	id crypto.ParticipantID,
	shareIndex int,
	dealer *crypto.Dealer,
) *crypto.Participant {
	t.Helper()

	p := new(crypto.Participant)

	if err := p.SetID(id); err != nil {
		t.Fatalf("failed to set %s ID: %v", name, err)
	}

	p.SetName(name)
	p.SetShare(dealer.GetParticipantShares(shareIndex))

	ok, err := p.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		t.Fatalf("%s consistency verification failed: %v", name, err)
	}
	if !ok {
		t.Fatalf("%s's share is NOT consistent with the commitment", name)
	}

	logOK(t, name+"'s share is consistent with the commitment")

	return p
}

func initParticipantSigner(
	t *testing.T,
	name string,
	p *crypto.Participant,
	P crypto.Point,
	ids []crypto.ParticipantID,
	sess *crypto.Session,
) *crypto.ParticipantSigner {
	t.Helper()

	ps := new(crypto.ParticipantSigner)

	ps.SetParticipant(p)
	ps.SetP(P)
	ps.SetIndices(ids)
	ps.SetSession(sess)

	if err := ps.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set %s Lagrange coefficient: %v", name, err)
	}

	logOK(t, name+" signer initialized")

	return ps
}

func verifyNonceFromParticipant(
	t *testing.T,
	server *crypto.ServerSigner,
	name string,
	ps *crypto.ParticipantSigner,
) {
	t.Helper()

	m1 := ps.GetMaterialToSend1()
	m2 := ps.GetMaterialToSend2()

	ok, err := server.VerifyNonce(&m1, &m2)
	if err != nil {
		t.Fatalf("server failed while verifying %s nonce: %v", name, err)
	}
	if !ok {
		t.Fatalf("server rejected %s nonce", name)
	}

	logOK(t, name+" nonce commitment verified")
}

func TestLSSSFullSigningFlow(t *testing.T) {
	logSection(t, "LSSS / VSS + Threshold Signing Test")

	n := 5
	k := 3

	// -------------------------------------------------------------------------
	// Dealer setup
	// -------------------------------------------------------------------------

	logSection(t, "Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate dealer secret: %v", err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate commitments and shares: %v", err)
	}

	logOK(t, "Dealer generated wallet secret, commitments, and shares")

	// -------------------------------------------------------------------------
	// Share consistency verification
	// -------------------------------------------------------------------------

	logSection(t, "Share consistency verification")

	Gianni := checkShareConsistency(t, "Gianni", 3, 2, dealer)
	Pino := checkShareConsistency(t, "Pino", 1, 0, dealer)
	Gino := checkShareConsistency(t, "Gino", 2, 1, dealer)
	Cornelio := checkShareConsistency(t, "Cornelio", 4, 3, dealer)
	Beppe := checkShareConsistency(t, "Beppe", 5, 4, dealer)

	_ = Gino
	_ = Beppe

	// -------------------------------------------------------------------------
	// Server and signing session setup
	// -------------------------------------------------------------------------

	logSection(t, "Server and signing session setup")

	S := new(crypto.Server)
	ServerS := new(crypto.ServerSigner)

	// IMPORTANT:
	// indices contains only the signing participants.
	// ServerID is handled separately by the protocol.
	ids := []crypto.ParticipantID{1, 3, 4}

	ServerS.SetP(P)
	ServerS.SetIndices(ids)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set server Lagrange coefficient: %v", err)
	}

	S.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	S.SetParams(&aux)

	ServerS.SetServer(*S)

	var sess crypto.Session
	id := []byte{1, 0, 0}
	if err := sess.SetID(id); err != nil {
		t.Fatalf("failed to set session ID: %v", err)
	}

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	ServerS.SetSession(&sess)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set server Lagrange coefficient after session setup: %v", err)
	}

	logOK(t, "Server signer initialized")
	logOK(t, "Signing session initialized")

	PinoS := initParticipantSigner(t, "Pino", Pino, P, ids, &sess)
	GianniS := initParticipantSigner(t, "Gianni", Gianni, P, ids, &sess)
	CornelioS := initParticipantSigner(t, "Cornelio", Cornelio, P, ids, &sess)

	// -------------------------------------------------------------------------
	// Nonce commitment phase
	// -------------------------------------------------------------------------

	logSection(t, "Nonce commitment phase")

	nonceServer := makeServerNonce(t, ServerS)
	noncePino := makeParticipantNonce(t, PinoS)
	nonceGianni := makeParticipantNonce(t, GianniS)
	nonceCornelio := makeParticipantNonce(t, CornelioS)

	logOK(t, "Private nonces and public nonce points generated")

	m1Server := makeMaterial1(t, nonceServer)
	m1Pino := makeMaterial1(t, noncePino)
	m1Gianni := makeMaterial1(t, nonceGianni)
	m1Cornelio := makeMaterial1(t, nonceCornelio)

	ServerS.SetMaterialToSend1(m1Server)
	PinoS.SetMaterialToSend1(m1Pino)
	GianniS.SetMaterialToSend1(m1Gianni)
	CornelioS.SetMaterialToSend1(m1Cornelio)

	logOK(t, "Nonce commitments generated")

	m2Server := makeMaterial2(t, nonceServer)
	m2Pino := makeMaterial2(t, noncePino)
	m2Gianni := makeMaterial2(t, nonceGianni)
	m2Cornelio := makeMaterial2(t, nonceCornelio)

	ServerS.SetMaterialToSend2(m2Server)
	PinoS.SetMaterialToSend2(m2Pino)
	GianniS.SetMaterialToSend2(m2Gianni)
	CornelioS.SetMaterialToSend2(m2Cornelio)

	logOK(t, "Nonce openings generated")

	verifyNonceFromParticipant(t, ServerS, "Pino", PinoS)
	verifyNonceFromParticipant(t, ServerS, "Gianni", GianniS)
	verifyNonceFromParticipant(t, ServerS, "Cornelio", CornelioS)

	// -------------------------------------------------------------------------
	// Aggregate nonce computation
	// -------------------------------------------------------------------------

	logSection(t, "Aggregate nonce computation")

	allM2 := []crypto.MaterialToSend2{
		m2Server,
		m2Pino,
		m2Gianni,
		m2Cornelio,
	}

	if err := ServerS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for server: %v", err)
	}
	if err := PinoS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Pino: %v", err)
	}
	if err := GianniS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Gianni: %v", err)
	}
	if err := CornelioS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Cornelio: %v", err)
	}

	logOK(t, "All signing parties computed the same aggregate nonce R")

	// -------------------------------------------------------------------------
	// Partial signature generation
	// -------------------------------------------------------------------------

	logSection(t, "Partial signature generation")

	msg := []byte("transaction made")

	if err := ServerS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute server partial signature: %v", err)
	}
	if err := PinoS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Pino partial signature: %v", err)
	}
	if err := GianniS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Gianni partial signature: %v", err)
	}
	if err := CornelioS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Cornelio partial signature: %v", err)
	}

	logOK(t, "Server partial signature generated")
	logOK(t, "Pino partial signature generated")
	logOK(t, "Gianni partial signature generated")
	logOK(t, "Cornelio partial signature generated")

	// -------------------------------------------------------------------------
	// Final signature combination
	// -------------------------------------------------------------------------

	logSection(t, "Final signature combination")

	zServer := ServerS.GetPartialSignature()
	zPino := PinoS.GetPartialSignature()
	zGianni := GianniS.GetPartialSignature()
	zCornelio := CornelioS.GetPartialSignature()

	// As in SetR, CombineSignature receives one contribution from each signing
	// party: the server and all participants in the session.
	allPartials := []crypto.PartialSignature{
		zServer,
		zPino,
		zGianni,
		zCornelio,
	}

	if err := ServerS.CombineSignature(allPartials); err != nil {
		t.Fatalf("server failed to combine threshold signature: %v", err)
	}

	sigServer := ServerS.GetSignature()

	logOK(t, "Server combined the final threshold signature")

	if err := PinoS.CombineSignature(allPartials); err != nil {
		t.Fatalf("Pino failed to combine threshold signature: %v", err)
	}

	sigPino := PinoS.GetSignature()

	logOK(t, "Pino combined the final threshold signature")

	if sigServer.R.Equal(&sigPino.R) != 1 {
		t.Fatalf("server-combined and Pino-combined signatures have different R")
	}

	if sigServer.Z.Equal(&sigPino.Z) != 1 {
		t.Fatalf("server-combined and Pino-combined signatures have different Z")
	}

	logOK(t, "Server-combined and Pino-combined signatures are identical")

	// -------------------------------------------------------------------------
	// Reconstruction sanity check
	// -------------------------------------------------------------------------

	logSection(t, "Reconstruction sanity check")

	lambdaServer := ServerS.GetLagrangeCoefficient()
	lambdaPino := PinoS.GetLagrangeCoefficient()
	lambdaGianni := GianniS.GetLagrangeCoefficient()
	lambdaCornelio := CornelioS.GetLagrangeCoefficient()

	server := ServerS.GetServer()
	pino := PinoS.GetParticipant()
	gianni := GianniS.GetParticipant()
	cornelio := CornelioS.GetParticipant()

	shareServer := server.GetShare()
	sharePino := pino.GetShare()
	shareGianni := gianni.GetShare()
	shareCornelio := cornelio.GetShare()

	var rec crypto.Scalar
	var tmp crypto.Scalar

	tmp.Multiply(&lambdaServer, &shareServer)
	rec.Add(&rec, &tmp)

	tmp.Multiply(&lambdaPino, &sharePino)
	rec.Add(&rec, &tmp)

	tmp.Multiply(&lambdaGianni, &shareGianni)
	rec.Add(&rec, &tmp)

	tmp.Multiply(&lambdaCornelio, &shareCornelio)
	rec.Add(&rec, &tmp)

	if rec.Equal(&secret) != 1 {
		t.Fatalf("reconstructed scalar does not match dealer secret")
	}

	logOK(t, "Reconstructed scalar matches dealer secret")

	var recP crypto.Point
	recP.ScalarBaseMult(&rec)

	var secretP crypto.Point
	secretP.ScalarBaseMult(&secret)

	if recP.Equal(&secretP) != 1 {
		t.Fatalf("reconstructed public key does not match dealer public key")
	}

	if P.Equal(&secretP) != 1 {
		t.Fatalf("dealer public key does not match secret-derived public key")
	}

	logOK(t, "Reconstructed public key matches dealer public key")

	// -------------------------------------------------------------------------
	// Final signature verification
	// -------------------------------------------------------------------------

	logSection(t, "Final signature verification")

	valid, err := crypto.VerifySignature(P, msg, sigServer, sess)
	if err != nil {
		t.Fatalf("server-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("server-combined final threshold signature is NOT valid")
	}

	logOK(t, "Server-combined final threshold signature verified successfully")

	valid, err = crypto.VerifySignature(P, msg, sigPino, sess)
	if err != nil {
		t.Fatalf("Pino-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("Pino-combined final threshold signature is NOT valid")
	}

	logOK(t, "Pino-combined final threshold signature verified successfully")
}

func TestParticipantRejectsTamperedShare(t *testing.T) {
	logSection(t, "Security Test: Participant Rejects Tampered Share")

	n := 5
	k := 3

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}
	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate dealer secret: %v", err)
	}

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}
	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate commitment and shares: %v", err)
	}

	logOK(t, "Dealer generated valid commitment and shares")

	p := new(crypto.Participant)

	if err := p.SetID(1); err != nil {
		t.Fatalf("failed to set participant ID: %v", err)
	}

	p.SetName("Pino")

	share := dealer.GetParticipantShares(0)

	var tamperedShare crypto.Scalar
	tamperedShare.Add(&share, &crypto.One)

	p.SetShare(tamperedShare)

	ok, err := p.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		t.Fatalf("VerifyConsistency returned unexpected error: %v", err)
	}

	if ok {
		t.Fatal("participant accepted a tampered share as valid")
	}

	logOK(t, "Participant correctly rejected the tampered share")
}

func TestTamperedPartialSignature(t *testing.T) {
	logSection(t, "Security Test: Tampered Partial Signature")

	n := 4
	k := 2

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("params failed: %v", err)
	}
	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("secret failed: %v", err)
	}

	friends := []string{"A", "B", "C", "D"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("friends failed: %v", err)
	}
	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("shares failed: %v", err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	// IMPORTANT:
	// indices contains only the signing participants.
	ids := []crypto.ParticipantID{1, 2}

	var sess crypto.Session
	if err := sess.SetID([]byte{0x11, 0x22, 0x33}); err != nil {
		t.Fatalf("failed to set session ID: %v", err)
	}
	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	server := new(crypto.Server)
	server.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server.SetParams(&aux)

	ss := new(crypto.ServerSigner)
	ss.SetServer(*server)
	ss.SetP(P)
	ss.SetIndices(ids)
	ss.SetSession(&sess)

	if err := ss.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server lagrange failed: %v", err)
	}

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p2 := checkShareConsistency(t, "P2", 2, 1, dealer)

	ps1 := initParticipantSigner(t, "P1", p1, P, ids, &sess)
	ps2 := initParticipantSigner(t, "P2", p2, P, ids, &sess)

	nonceServer := makeServerNonce(t, ss)
	nonce1 := makeParticipantNonce(t, ps1)
	nonce2 := makeParticipantNonce(t, ps2)

	allM2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer),
		makeMaterial2(t, nonce1),
		makeMaterial2(t, nonce2),
	}

	if err := ss.SetR(allM2); err != nil {
		t.Fatalf("server SetR failed: %v", err)
	}
	if err := ps1.SetR(allM2); err != nil {
		t.Fatalf("ps1 SetR failed: %v", err)
	}
	if err := ps2.SetR(allM2); err != nil {
		t.Fatalf("ps2 SetR failed: %v", err)
	}

	msg := []byte("hello")

	if err := ss.SetPartialSignature(msg); err != nil {
		t.Fatalf("server partial signature failed: %v", err)
	}
	if err := ps1.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps1 partial signature failed: %v", err)
	}
	if err := ps2.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps2 partial signature failed: %v", err)
	}

	tampered := ps1.GetPartialSignature()

	// Tamper with P1's partial signature while keeping its index unchanged.
	tampered.Z.Add(&tampered.Z, &crypto.One)

	attacked := []crypto.PartialSignature{
		ss.GetPartialSignature(),
		tampered,
		ps2.GetPartialSignature(),
	}

	if err := ss.CombineSignature(attacked); err != nil {
		t.Fatalf("combine failed unexpectedly: %v", err)
	}

	sig := ss.GetSignature()

	valid, err := crypto.VerifySignature(P, msg, sig, sess)
	if err != nil {
		t.Fatalf("VerifySignature returned unexpected error: %v", err)
	}

	if valid {
		t.Fatalf("tampered partial signature produced a valid final signature")
	}

	logOK(t, "Tampered partial signature produced an invalid final signature")
}

func TestReplayAttackDifferentSession(t *testing.T) {
	logSection(t, "Security Test: Replay Attack Across Sessions")

	n := 5
	k := 3

	// -------------------------------------------------------------------------
	// Dealer setup
	// -------------------------------------------------------------------------

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed params: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed secret: %v", err)
	}

	friends := []string{"A", "B", "C", "D", "E"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed shares: %v", err)
	}

	secret := dealer.GetSecret()

	var P crypto.Point
	P.ScalarBaseMult(&secret)

	// IMPORTANT:
	// indices contains only the signing participants.
	// ServerID is handled separately by the protocol.
	ids := []crypto.ParticipantID{1, 3, 4}

	msg := []byte("hello")

	// -------------------------------------------------------------------------
	// Share consistency verification
	// -------------------------------------------------------------------------

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p3 := checkShareConsistency(t, "P3", 3, 2, dealer)
	p4 := checkShareConsistency(t, "P4", 4, 3, dealer)

	// =========================================================================
	// Session 1: legitimate session from which we steal one old partial
	// =========================================================================

	logSection(t, "Session 1 setup")

	var sess1 crypto.Session
	if err := sess1.SetID([]byte{1, 0, 0}); err != nil {
		t.Fatalf("failed session1 ID: %v", err)
	}
	sess1.SetIndices(ids)
	sess1.SetIndexHash(ids)

	server1 := new(crypto.Server)
	server1.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server1.SetParams(&aux)

	serverSigner1 := new(crypto.ServerSigner)
	serverSigner1.SetServer(*server1)
	serverSigner1.SetP(P)
	serverSigner1.SetIndices(ids)
	serverSigner1.SetSession(&sess1)

	if err := serverSigner1.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server1 lagrange failed: %v", err)
	}

	ps1Sess1 := initParticipantSigner(t, "P1-S1", p1, P, ids, &sess1)
	ps3Sess1 := initParticipantSigner(t, "P3-S1", p3, P, ids, &sess1)
	ps4Sess1 := initParticipantSigner(t, "P4-S1", p4, P, ids, &sess1)

	nonceServer1 := makeServerNonce(t, serverSigner1)
	nonceP1S1 := makeParticipantNonce(t, ps1Sess1)
	nonceP3S1 := makeParticipantNonce(t, ps3Sess1)
	nonceP4S1 := makeParticipantNonce(t, ps4Sess1)

	allM2Sess1 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer1),
		makeMaterial2(t, nonceP1S1),
		makeMaterial2(t, nonceP3S1),
		makeMaterial2(t, nonceP4S1),
	}

	if err := serverSigner1.SetR(allM2Sess1); err != nil {
		t.Fatalf("server1 SetR failed: %v", err)
	}
	if err := ps1Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P1 session1 SetR failed: %v", err)
	}
	if err := ps3Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P3 session1 SetR failed: %v", err)
	}
	if err := ps4Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P4 session1 SetR failed: %v", err)
	}

	if err := serverSigner1.SetPartialSignature(msg); err != nil {
		t.Fatalf("server1 partial failed: %v", err)
	}
	if err := ps1Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P1 session1 partial failed: %v", err)
	}
	if err := ps3Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P3 session1 partial failed: %v", err)
	}
	if err := ps4Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P4 session1 partial failed: %v", err)
	}

	// Replay target: old P1 partial from session 1.
	replayedPartial := ps1Sess1.GetPartialSignature()

	logOK(t, "Session 1 partial signatures generated")

	// =========================================================================
	// Session 2: attack target
	// =========================================================================

	logSection(t, "Session 2 setup")

	var sess2 crypto.Session
	if err := sess2.SetID([]byte{9, 9, 9}); err != nil {
		t.Fatalf("failed session2 ID: %v", err)
	}
	sess2.SetIndices(ids)
	sess2.SetIndexHash(ids)

	server2 := new(crypto.Server)
	server2.SetShare(dealer.GetServerShare())
	server2.SetParams(&aux)

	serverSigner2 := new(crypto.ServerSigner)
	serverSigner2.SetServer(*server2)
	serverSigner2.SetP(P)
	serverSigner2.SetIndices(ids)
	serverSigner2.SetSession(&sess2)

	if err := serverSigner2.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server2 lagrange failed: %v", err)
	}

	ps1Sess2 := initParticipantSigner(t, "P1-S2", p1, P, ids, &sess2)
	ps3Sess2 := initParticipantSigner(t, "P3-S2", p3, P, ids, &sess2)
	ps4Sess2 := initParticipantSigner(t, "P4-S2", p4, P, ids, &sess2)

	nonceServer2 := makeServerNonce(t, serverSigner2)
	nonceP1S2 := makeParticipantNonce(t, ps1Sess2)
	nonceP3S2 := makeParticipantNonce(t, ps3Sess2)
	nonceP4S2 := makeParticipantNonce(t, ps4Sess2)

	allM2Sess2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer2),
		makeMaterial2(t, nonceP1S2),
		makeMaterial2(t, nonceP3S2),
		makeMaterial2(t, nonceP4S2),
	}

	if err := serverSigner2.SetR(allM2Sess2); err != nil {
		t.Fatalf("server2 SetR failed: %v", err)
	}
	if err := ps1Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P1 session2 SetR failed: %v", err)
	}
	if err := ps3Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P3 session2 SetR failed: %v", err)
	}
	if err := ps4Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P4 session2 SetR failed: %v", err)
	}

	if err := serverSigner2.SetPartialSignature(msg); err != nil {
		t.Fatalf("server2 partial failed: %v", err)
	}
	if err := ps1Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P1 session2 partial failed: %v", err)
	}
	if err := ps3Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P3 session2 partial failed: %v", err)
	}
	if err := ps4Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P4 session2 partial failed: %v", err)
	}

	logOK(t, "Session 2 fresh partial signatures generated")

	// -------------------------------------------------------------------------
	// Attack:
	// replace P1's fresh session2 partial with P1's old session1 partial.
	// -------------------------------------------------------------------------

	logSection(t, "Replay attack attempt")

	attackedPartials := []crypto.PartialSignature{
		serverSigner2.GetPartialSignature(),
		replayedPartial, // old P1 partial from session 1
		ps3Sess2.GetPartialSignature(),
		ps4Sess2.GetPartialSignature(),
	}

	// CombineSignature only aggregates structurally valid partial signatures.
	// The replay is detected by final signature verification, because the old
	// partial was computed with a different session/challenge.
	if err := serverSigner2.CombineSignature(attackedPartials); err != nil {
		t.Fatalf("combine failed unexpectedly: %v", err)
	}

	sig := serverSigner2.GetSignature()

	valid, err := crypto.VerifySignature(P, msg, sig, sess2)
	if err != nil {
		t.Fatalf("VerifySignature returned unexpected error: %v", err)
	}

	if valid {
		t.Fatalf("replayed partial from session1 produced a valid signature in session2")
	}

	logOK(t, "Replay attack produced an invalid final signature")
}
