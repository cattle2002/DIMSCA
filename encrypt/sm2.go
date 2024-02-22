package encrypt

import (
	"DIMSCA/config"
	"DIMSCA/pkg"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"time"
)

func GenSm2() (string, string, int64, error) {

	if config.ConfCa.KeyPair.PrivateKeyStoreKey == "" {
		config.ConfCa.KeyPair.PrivateKeyStoreKey = pkg.Sm2DefaultKey
	}
	tmpKey, err := hex.DecodeString(config.ConfCa.KeyPair.PrivateKeyStoreKey)
	if err != nil {
		return "", "", 0, err
	}
	Kp, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", 0, err
	}
	Pk, err := x509.WritePublicKeyToPem(&Kp.PublicKey)
	if err != nil {
		return "", "", 0, err
	}

	Sk, err := x509.WritePrivateKeyToPem(Kp, tmpKey)
	if err != nil {
		return "", "", 0, err
	}
	return string(Pk), string(Sk), time.Now().UnixMilli(), nil
}
func Sm2Encrypt(pk string, data []byte) (string, error) {
	publicKey, err := x509.ReadPublicKeyFromPem([]byte(pk))
	if err != nil {
		return "", err
	}
	encrypt, err := sm2.Encrypt(publicKey, data, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return "", err
	} else {
		toString := hex.EncodeToString(encrypt)
		return toString, nil
	}
}
func Sm2Decrypt(sk string, data []byte) (string, error) {
	decodeString, err := hex.DecodeString(string(data))
	if err != nil {
		return "", err
	}
	tmpKey, err := hex.DecodeString(config.ConfCa.KeyPair.PrivateKeyStoreKey)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ReadPrivateKeyFromPem([]byte(sk), tmpKey)
	if err != nil {
		return "", err
	}
	decrypt, err := sm2.Decrypt(privateKey, decodeString, sm2.C1C3C2)
	if err != nil {
		return "", err
	} else {
		//toString := string(decrypt)
		toString := base64.StdEncoding.EncodeToString(decrypt)
		return toString, nil
	}
}
