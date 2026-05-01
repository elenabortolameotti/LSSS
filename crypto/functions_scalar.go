package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

func scalarOne() Scalar {
	var one Scalar

	b := make([]byte, 32)
	b[0] = 1

	if _, err := one.SetCanonicalBytes(b); err != nil {
		panic(err)
	}

	return one
}

func SetAlpha() Scalar {
	g := new(Scalar)
	g.SetCanonicalBytes([]byte{
		2, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	return *g
}

func ScalarPow(base *Scalar, exp uint8, s *Scalar) {
	result := One
	power := edwards25519.NewScalar().Set(base)

	for exp > 0 {
		if exp&1 == 1 {
			result.Multiply(&result, power)
		}

		power.Multiply(power, power)
		exp >>= 1
	}

	*s = result
	result = Scalar{} // zeroization of result
	*power = Scalar{} // zeroization of power
}

func generateRandomScalar(s *Scalar) error {

	buf := make([]byte, 64)

	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Errorf("generateRandomScalar failed: %w", err)
	}

	aus, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		*aus = Scalar{} // zeroization of aus
		return fmt.Errorf("generateRandomScalar failed: %w", err)
	}
	*s = *aus
	*aus = Scalar{} // zeroization of s

	return nil
}

func generateRandomScalars(scalars []Scalar) error {

	buf := make([]byte, 64)

	var s *Scalar
	var err error

	for i := 0; i < len(scalars); i++ {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return fmt.Errorf("generateRandomScalars failed: %w", err)
		}

		s, err = edwards25519.NewScalar().SetUniformBytes(buf[:])
		if err != nil {
			*s = Scalar{} // zeroization of s
			return fmt.Errorf("generateRandomScalars failed: %w", err)
		}
		scalars[i] = *s
		*s = Scalar{} // zeroization of s
	}
	return nil
}

var One = scalarOne()
var alpha = SetAlpha()

func NewProtocol(alpha *Scalar, k, n int) *Protocol {
	return &Protocol{
		PP: PublicParams{
			K: k,
			N: n,
			M: BuildM(alpha, k, n),
		},
		Alpha: *alpha,
	}
}

func (p *Protocol) Distribute(v *SecretVector) DealerShares {
	// beta1 = s + r2
	var beta1 Scalar
	beta1.Add(&v.S, &v.R2)

	var beta2 Scalar
	beta2.Multiply(&v.R2, &p.Alpha)
	beta2.Add(&beta2, &v.S)

	// gamma_i = beta2 + t_1*alpha^(i-1) + t_2*alpha^(2(i-1)) + ... + t_{k-1}*alpha^((k-1)(i-1))
	participantShares := make([]Scalar, p.PP.N)
	for i := 0; i < p.PP.N; i++ {
		var share Scalar
		share.Set(&beta2)
		for j := 0; j < p.PP.K-1; j++ {
			var term Scalar
			term.Multiply(&v.T[j], &p.PP.M[j+2][i+1]) // M[j+2][i+1] = alpha^((j)(i))
			share.Add(&share, &term)
		}
		participantShares[i].Set(&share)
	}

	return DealerShares{
		ServerShare:       beta1,
		ParticipantShares: participantShares,
	}

}

func CoefficientsForSecret(M Matrix, n int, indices []ParticipantID) []Scalar {
	alpha := &M[1][1]

	one := scalarOne()

	var alphaMinusOne Scalar
	alphaMinusOne.Subtract(alpha, &one) // alpha - 1

	var invAlphaMinusOne Scalar
	invAlphaMinusOne.Invert(&alphaMinusOne) // 1 / (alpha - 1)

	var minusOne Scalar
	minusOne.Negate(&one) // -1

	var coeffLambda2 Scalar
	coeffLambda2.Multiply(&minusOne, &invAlphaMinusOne) // -1 / (alpha - 1)

	// vettore finale lungo n, inizialmente tutto zero
	cis := make([]Scalar, n)
	for i := 0; i < n; i++ {
		cis[i].Set(edwards25519.NewScalar()) // zero
	}

	if len(indices) == 0 {
		return cis
	}

	// indices è ordinato, quindi l'ultimo è il massimo
	maxIdx := int(indices[len(indices)-1])
	if maxIdx <= 0 || maxIdx > n {
		panic("participant index out of range")
	}

	powers := computePowers(alpha, maxIdx)

	m := len(indices)

	// xs = alpha^i per i negli indici selezionati
	xs := make([]Scalar, m)
	for i, idx := range indices {
		if int(idx) <= 0 || int(idx) > n {
			panic("participant index out of range")
		}
		xs[i].Set(&powers[int(idx)])
	}

	// lambda puri di Lagrange:
	// lambda_i = Π_{j != i} x_j / (x_j - x_i)
	lambdas := make([]Scalar, m)
	for i := 0; i < m; i++ {
		lambdas[i].Set(&one)

		for j := 0; j < m; j++ {
			if i == j {
				continue
			}

			var den Scalar
			den.Subtract(&xs[j], &xs[i]) // x_j - x_i

			var denInv Scalar
			denInv.Invert(&den)

			var factor Scalar
			factor.Multiply(&xs[j], &denInv) // x_j / (x_j - x_i)

			lambdas[i].Multiply(&lambdas[i], &factor)
		}
	}

	// c_i = (-1/(alpha-1)) * lambda_i
	// e lo mettiamo nella posizione del partecipante
	for i, idx := range indices {
		pos := int(idx) - 1 // partecipanti numerati da 1 a n
		cis[pos].Multiply(&coeffLambda2, &lambdas[i])
	}

	return cis
}
