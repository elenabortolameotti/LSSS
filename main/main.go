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

}
