package crypto

import "filippo.io/edwards25519"

// General
type Point = edwards25519.Point
type Scalar = edwards25519.Scalar
type Matrix [][]Scalar
type ParticipantID int

// Signature scheme
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

// Protocol
type PublicParams struct {
	K int // soglia
	N int // numero di partecipanti (utenti)
	M Matrix
}

type Protocol struct {
	PP    PublicParams
	Alpha Scalar
}

// Other structs
type DealerShares struct {
	ServerShare       Scalar   // beta1
	ParticipantShares []Scalar // gamma1,...,gamman
}

type SecretVector struct {
	S  Scalar   // segreto
	R2 Scalar   // coefficiente per p1
	T  []Scalar // t1,...,t_{k-1}
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

//Session
type Session struct {
	ID        []byte
	Indices   []ParticipantID
	IndexHash []byte
}
