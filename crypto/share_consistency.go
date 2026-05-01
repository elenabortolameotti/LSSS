package crypto

import "filippo.io/edwards25519"

func (p *Protocol) VerifyShare(participantID ParticipantID, share Scalar, commitments Commitments) bool {
	if int(participantID) < 1 || int(participantID) > p.PP.N {
		return false
	}
	if len(commitments.Points) != p.PP.K+1 {
		return false
	}

	col := int(participantID) // se participantID è 1..n

	lhs := edwards25519.NewIdentityPoint()

	for j := 0; j < p.PP.K+1; j++ {
		var term Point
		term.ScalarMult(&p.PP.M[j][col], &commitments.Points[j])
		lhs.Add(lhs, &term)
	}

	var rhs Point
	rhs.ScalarBaseMult(&share)

	return lhs.Equal(&rhs) == 1
}
