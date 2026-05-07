package main

import (
	"fmt"

	"github.com/elenabortolameotti/LSSS/crypto"
)

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

	GianniS := new(crypto.ParticipantSigner)

	GianniS.SetParticipant(Gianni)
	ids := []crypto.ParticipantID{1, 3, 4}
	GianniS.SetIndices(ids)
	GianniS.SetLagrangeCoefficient()

	lambdaGianni := GianniS.GetLagrangeCoefficient()

	// Stampa il coefficiente di Lagrange di Gianni
	fmt.Println(lambdaGianni)

	//Controlliamo la correttezza dei coefficienti di Lagrange

	participants := make([]*crypto.ParticipantSigner, len(ids))
	for i, id := range ids {
		p := new(crypto.Participant)
		ps := new(crypto.ParticipantSigner)
		err := p.SetID(id)
		if err != nil {
			panic(err)
		}

		p.SetName(friends[id-1])
		p.SetShare(dealer.GetParticipantShares(int(id - 1)))

		ok, err := p.VerifyConsistency(*dealer.GetComm())
		if err != nil {
			panic(err)
		}

		fmt.Printf("Participant %d consistent: %v\n", id, ok)
		ps.SetParticipant(p)
		ps.SetIndices(ids)
		ps.SetLagrangeCoefficient()

		aus := ps.GetLagrangeCoefficient()
		fmt.Printf(
			"Participant %d: %x\n",
			id,
			(&aus).Bytes(),
		)

		participants[i] = ps
	}

	server := new(crypto.Server)
	servers := new(crypto.ServerSigner)
	server.SetShare(dealer.GetServerShare())
	servers.SetServer(*server)
	boolServerConsistent, err := server.VerifyConsistency(dealer.GetComm())
	if err != nil {
		panic(err)
	}
	if boolServerConsistent {
		fmt.Println("Server's share is consistent with the commitment.")
	} else {
		fmt.Println("Server's share is NOT consistent with the commitment.")
	}
	servers.SetIndices(ids)
	servers.SetLagrangeCoefficient()

	aus2 := servers.GetLagrangeCoefficient()
	fmt.Printf("Lambda server: %x\n", (&aus2).Bytes())

	var reconstructed crypto.Scalar
	var term crypto.Scalar

	aus3 := server.GetShare()
	aus4 := servers.GetLagrangeCoefficient()

	// reconstructed += lambda_server * server_share
	term.Multiply(&aus3, &aus4)
	reconstructed.Add(&reconstructed, &term)

	// reconstructed += lambda_i * share_i
	for _, ps := range participants {
		lambda := ps.GetLagrangeCoefficient()
		share := ps.GetParticipant().GetShare()

		term.Multiply(&lambda, &share)
		reconstructed.Add(&reconstructed, &term)
	}

	secret := dealer.GetSecret()

	fmt.Printf("Dealer secret:  %x\n", secret.Bytes())
	fmt.Printf("Reconstructed:  %x\n", reconstructed.Bytes())

	if reconstructed.Equal(&secret) == 1 {
		fmt.Println("Secret reconstructed correctly")
	} else {
		fmt.Println("Secret reconstruction failed")
	}
}
