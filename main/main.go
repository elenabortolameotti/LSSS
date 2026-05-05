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

	Gianni.SetShare(dealer.GetShares(3))

	IsConsistent, err := Gianni.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		panic(err)
	}

	fmt.Println(IsConsistent)
}
