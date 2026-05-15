package main

import (
	"fmt"

	"github.com/elenabortolameotti/LSSS/crypto"
)

var a crypto.Scalar

func makeParticipantNonce(ps *crypto.ParticipantSigner) crypto.NonceShare {
	var nonce crypto.NonceShare

	if err := nonce.SetIndex(ps.GetParticipant().GetID()); err != nil {
		panic(err)
	}

	if err := nonce.Setri(); err != nil {
		panic(err)
	}

	if err := nonce.SetRi(); err != nil {
		panic(err)
	}

	sess := ps.GetSession()
	nonce.SetCommit(&sess)

	ps.SetN(nonce)

	return nonce
}

func makeServerNonce(ss *crypto.ServerSigner) crypto.NonceShare {

	var nonce crypto.NonceShare

	if err := nonce.SetIndex(crypto.ServerID); err != nil {
		panic(err)
	}

	if err := nonce.Setri(); err != nil {
		panic(err)
	}

	if err := nonce.SetRi(); err != nil {
		panic(err)
	}

	sess := ss.GetSession()
	nonce.SetCommit(&sess)

	ss.SetNonce(nonce)

	return nonce
}

func makeMaterial1(n crypto.NonceShare) crypto.MaterialToSend1 {
	ci, err := n.GetCommit()
	if err != nil {
		panic(err)
	}

	var m crypto.MaterialToSend1
	m.SetIndex(n.GetIndex())
	m.SetCommit(ci)

	return m
}

func makeMaterial2(n crypto.NonceShare) crypto.MaterialToSend2 {
	Ri, err := n.GetRi()
	if err != nil {
		panic(err)
	}

	var m crypto.MaterialToSend2
	m.SetIndex(n.GetIndex())
	m.SetRi(*Ri)

	return m
}

func main() {
	// Esempio di utilizzo del protocollo
	n := 5 // numero totale di partecipanti
	k := 3 // soglia
	dealer := new(crypto.Dealer)
	err := dealer.SetTsParameters(n, k)
	if err != nil {
		panic(err)
	}

	err = dealer.SetSecret()
	if err != nil {
		panic(err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	err = dealer.SetFriends(friends)
	if err != nil {
		panic(err)
	}

	err = dealer.SetCommAndShares()
	if err != nil {
		panic(err)
	}
	// se non panica, il dealer è correttamente settato

	Gianni := new(crypto.Participant)

	err = Gianni.SetID(3)
	if err != nil {
		panic(err)
	}

	Gianni.SetName("Gianni")

	Gianni.SetShare(dealer.GetParticipantShares(2))

	IsConsistent, err := Gianni.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	// Se non panica, la verifica di consistenza è stata eseguita correttamente
	if IsConsistent {
		fmt.Println("Gianni's share is consistent with the commitment.")
	} else {
		fmt.Println("Gianni's share is NOT consistent with the commitment.")
	}

	Pino := new(crypto.Participant)

	err = Pino.SetID(1)
	if err != nil {
		panic(err)
	}

	pinoID := Pino.GetID()
	fmt.Println(pinoID)

	Pino.SetName("Pino")

	Pino.SetShare(dealer.GetParticipantShares(0))

	IsConsistent2, err := Pino.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	// Se non panica, la verifica di consistenza è stata eseguita correttamente
	if IsConsistent2 {
		fmt.Println("Pino's share is consistent with the commitment.")
	} else {
		fmt.Println("Pino's share is NOT consistent with the commitment.")
	}

	Gino := new(crypto.Participant)

	err = Gino.SetID(2)
	if err != nil {
		panic(err)
	}

	Gino.SetName("Gino")

	Gino.SetShare(dealer.GetParticipantShares(1))

	IsConsistent3, err := Gino.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	// Se non panica, la verifica di consistenza è stata eseguita correttamente
	if IsConsistent3 {
		fmt.Println("Gino's share is consistent with the commitment.")
	} else {
		fmt.Println("Gino's share is NOT consistent with the commitment.")
	}

	Cornelio := new(crypto.Participant)

	err = Cornelio.SetID(4)
	if err != nil {
		panic(err)
	}

	Cornelio.SetName("Cornelio")

	Cornelio.SetShare(dealer.GetParticipantShares(3))

	IsConsistent4, err := Cornelio.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	// Se non panica, la verifica di consistenza è stata eseguita correttamente
	if IsConsistent4 {
		fmt.Println("Cornelio's share is consistent with the commitment.")
	} else {
		fmt.Println("Cornelio's share is NOT consistent with the commitment.")
	}

	Beppe := new(crypto.Participant)

	err = Beppe.SetID(5)
	if err != nil {
		panic(err)
	}

	Beppe.SetName("Beppe")

	Beppe.SetShare(dealer.GetParticipantShares(4))

	IsConsistent5, err := Beppe.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	// Se non panica, la verifica di consistenza è stata eseguita correttamente
	if IsConsistent5 {
		fmt.Println("Beppe's share is consistent with the commitment.")
	} else {
		fmt.Println("Beppe's share is NOT consistent with the commitment.")
	}

	S := new(crypto.Server)
	ServerS := new(crypto.ServerSigner)

	ids := []crypto.ParticipantID{1, 3, 4}

	ServerS.SetP(P)
	ServerS.SetIndices(ids)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		panic(err)
	}

	S.SetShare(dealer.GetServerShare())
	aux := dealer.GetTsParameters()
	S.SetParams(&aux)

	ServerS.SetServer(*S)

	var sess crypto.Session

	vec := []byte{1, 1, 1, 1, 1, 1}
	if err := sess.SetID(vec); err != nil {
		panic(err)
	}

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	ServerS.SetSession(&sess)
	ServerS.SetLagrangeCoefficient()
	PinoS := new(crypto.ParticipantSigner)
	PinoS.SetParticipant(Pino)
	PinoS.SetP(P)
	PinoS.SetIndices(ids)
	PinoS.SetSession(&sess)

	if err := PinoS.SetLagrangeCoefficient(); err != nil {
		panic(err)
	}

	GianniS := new(crypto.ParticipantSigner)
	GianniS.SetParticipant(Gianni)
	GianniS.SetP(P)
	GianniS.SetIndices(ids)
	GianniS.SetSession(&sess)
	if err := GianniS.SetLagrangeCoefficient(); err != nil {
		panic(err)
	}

	CornelioS := new(crypto.ParticipantSigner)
	CornelioS.SetParticipant(Cornelio)
	CornelioS.SetP(P)
	CornelioS.SetIndices(ids)
	CornelioS.SetSession(&sess)
	if err := CornelioS.SetLagrangeCoefficient(); err != nil {
		panic(err)
	}

	nonceServer := makeServerNonce(ServerS)
	noncePino := makeParticipantNonce(PinoS)
	nonceGianni := makeParticipantNonce(GianniS)
	nonceCornelio := makeParticipantNonce(CornelioS)

	m1Server := makeMaterial1(nonceServer)
	m1Pino := makeMaterial1(noncePino)
	m1Gianni := makeMaterial1(nonceGianni)
	m1Cornelio := makeMaterial1(nonceCornelio)

	ServerS.SetMaterialToSend1(m1Server)
	PinoS.SetMaterialToSend1(m1Pino)
	GianniS.SetMaterialToSend1(m1Gianni)
	CornelioS.SetMaterialToSend1(m1Cornelio)

	m2Server := makeMaterial2(nonceServer)
	m2Pino := makeMaterial2(noncePino)
	m2Gianni := makeMaterial2(nonceGianni)
	m2Cornelio := makeMaterial2(nonceCornelio)

	ServerS.SetMaterialToSend2(m2Server)
	PinoS.SetMaterialToSend2(m2Pino)
	GianniS.SetMaterialToSend2(m2Gianni)
	CornelioS.SetMaterialToSend2(m2Cornelio)

	//serverM1 := ServerS.GetMaterialToSend1()
	pinoM1 := PinoS.GetMaterialToSend1()
	gianniM1 := GianniS.GetMaterialToSend1()
	cornelioM1 := CornelioS.GetMaterialToSend1()

	//serverM2 := ServerS.GetMaterialToSend2()
	pinoM2 := PinoS.GetMaterialToSend2()
	gianniM2 := GianniS.GetMaterialToSend2()
	cornelioM2 := CornelioS.GetMaterialToSend2()

	// Verify nonces
	ok, err := ServerS.VerifyNonce(&pinoM1, &pinoM2)
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("ServerS rejected Pino nonce")
	}

	ok, err = ServerS.VerifyNonce(&gianniM1, &gianniM2)
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("ServerS rejected Gianni nonce")
	}

	ok, err = ServerS.VerifyNonce(&cornelioM1, &cornelioM2)
	if err != nil {
		panic(err)
	}
	if !ok {
		panic("ServerS rejected Cornelio nonce")
	}

	allM2 := []crypto.MaterialToSend2{
		m2Server,
		m2Pino,
		m2Gianni,
		m2Cornelio,
	}

	err = ServerS.SetR(allM2)
	if err != nil {
		panic(err)
	}

	err = PinoS.SetR(allM2)
	if err != nil {
		panic(err)
	}

	err = GianniS.SetR(allM2)
	if err != nil {
		panic(err)
	}

	err = CornelioS.SetR(allM2)
	if err != nil {
		panic(err)
	}

	msg := []byte("transaction made")

	err = ServerS.SetPartialSignature(msg)
	if err != nil {
		panic(err)
	}

	err = PinoS.SetPartialSignature(msg)
	if err != nil {
		panic(err)
	}

	err = GianniS.SetPartialSignature(msg)
	if err != nil {
		panic(err)
	}

	err = CornelioS.SetPartialSignature(msg)
	if err != nil {
		panic(err)
	}

	zPino := PinoS.GetPartialSignature()
	zGianni := GianniS.GetPartialSignature()
	zCornelio := CornelioS.GetPartialSignature()
	zServer := ServerS.GetPartialSignature()

	partialsForServer := []crypto.PartialSignature{
		zServer,
		zPino,
		zGianni,
		zCornelio,
	}

	err = ServerS.CombineSignature(partialsForServer)
	if err != nil {
		panic(err)
	}

	sig := ServerS.GetSignature()

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

	fmt.Println("rec == dealer.GetSecret():", rec.Equal(&secret) == 1)

	var recP crypto.Point
	recP.ScalarBaseMult(&rec)

	var secretP crypto.Point
	secretP.ScalarBaseMult(&secret)

	fmt.Printf("recP:    %x\n", recP.Bytes())
	fmt.Printf("secretP: %x\n", secretP.Bytes())
	fmt.Println("recP == secretP:", recP.Equal(&secretP) == 1)
	fmt.Println("P == secretP:", P.Equal(&secretP) == 1)

	fmt.Println("Final signature generated:")
	fmt.Println(sig)

	bool, err := crypto.VerifySignature(P, msg, sig, sess)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(bool)
}
