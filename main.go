package main

import (
	_ "crypto/sha256"
	"fmt"

	b "blind/basket"
	c "blind/client"
	r "blind/reestr"
)

func main() {

	// новые рессестр
	reestr, err := r.New(2048)
	if err != nil {
		panic("1::" + err.Error())
	}

	// новый клиент
	cli := c.New([]byte("SECRET"), 1536, reestr.PublicKey())

	// новая урна
	basket := b.New(reestr.PublicKey())

	// клиент::подписывает зашифрованную строку публичным ключем ПЦР
	blinded, err := cli.Blind()
	if err != nil {
		panic("2::" + err.Error())
	}

	// клиент вызывает ПЦР и передает ему данные
	pcrSig, err := reestr.BlindSign(blinded)
	if err != nil {
		panic("3::" + err.Error())
	}

	// клиент::снимает свою подпись
	cliUnBlindedSig := cli.UnBlind(pcrSig)

	// Урна получает от Клиента данные и валидирует
	if err = basket.Verify(cli.Hash(), cliUnBlindedSig); err != nil {
		panic("4::failed to verify signature" + err.Error())
	} else {
		fmt.Println("ALL IS WELL")
	}
}
