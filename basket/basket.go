package basket

import (
	"crypto/rsa"

	"github.com/cryptoballot/rsablind"
)

// -------------- Урна ---------
type Basket struct {
	prcPubKey rsa.PublicKey
}

func New(prcPubKey rsa.PublicKey) *Basket {
	return &Basket{prcPubKey: prcPubKey}
}

func (b *Basket) Verify(hash, unBlindedSig []byte) error {
	if err := rsablind.VerifyBlindSignature(&b.prcPubKey, hash, unBlindedSig); err != nil {
		return err
	}
	return nil
}
