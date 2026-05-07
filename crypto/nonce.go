package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

// commitNonce calcola H(sess.ID || sess.IndexHash || index || Ri).
func commitNonce(sess *Session, index ParticipantID, Ri []byte) []byte {
	h := sha256.New()
	h.Write(sess.id)
	h.Write(sess.indexHash)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(index))
	h.Write(tmp[:])

	h.Write(Ri)
	return h.Sum(nil)
}

func VerifyNonceAux(sess *Session, index ParticipantID, commit, Ri []byte) (bool, error) {
	if sess == nil {
		return false, errors.New("VerifyNonceAux failed: sess is nil")
	}

	if !sess.HasParticipant(index) {
		return false, errors.New("VerifyNonceAux failed: index is not a participant of the session")
	}

	if len(commit) != sha256.Size {
		return false, errors.New("VerifyNonceAux failed: commit has incorrect length")
	}

	var R edwards25519.Point
	if _, err := R.SetBytes(Ri); err != nil {
		return false, errors.New("VerifyNonceAux failed: failed to set Ri")
	}

	sum := commitNonce(sess, index, Ri)
	return subtle.ConstantTimeCompare(sum, commit) == 1, nil
}
