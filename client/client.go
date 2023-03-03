package clietn

import (
	"crypto"
	"crypto/rsa"

	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
)

type Client struct {
	message   []byte
	size      int
	hash      []byte
	blinded   []byte
	unBlinder []byte
	prcPubKey rsa.PublicKey
}

func New(s []byte, size int, k rsa.PublicKey) *Client {
	return &Client{
		message:   s,
		size:      size,
		hash:      fdh.Sum(crypto.SHA256, size, s),
		prcPubKey: k,
	}
}

func (c *Client) Hash() []byte {
	return c.hash
}

func (c *Client) Blind() ([]byte, error) {
	var err error
	c.blinded, c.unBlinder, err = rsablind.Blind(&c.prcPubKey, c.hash)
	if err != nil {
		return nil, err
	}
	return c.blinded, nil
}

func (c *Client) UnBlinder() []byte {
	return c.unBlinder
}

func (c *Client) UnBlind(sig []byte) []byte {
	return rsablind.Unblind(&c.prcPubKey, sig, c.unBlinder)
}
