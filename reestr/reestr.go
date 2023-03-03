package reestr

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/cryptoballot/rsablind"
)

type Reestr struct {
	size int
	key  *rsa.PrivateKey
}

func New(size int) (*Reestr, error) {
	var err error
	r := Reestr{
		size: size,
	}
	r.key, err = rsa.GenerateKey(rand.Reader, r.size)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Reestr) PublicKey() rsa.PublicKey {
	return r.key.PublicKey
}

func (r *Reestr) BlindSign(b []byte) ([]byte, error) {
	return rsablind.BlindSign(r.key, b)
}
