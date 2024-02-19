package encrypt

import (
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func Gensm2() (string, string, error) {
	Kp, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	Pk, err := x509.WritePublicKeyToPem(&Kp.PublicKey)
	if err != nil {
		return "", "", err
	}
	Sk, err := x509.WritePrivateKeyToPem(Kp, []byte("12345678"))
	if err != nil {
		return "", "", err
	}
	return string(Pk), string(Sk), nil
}
