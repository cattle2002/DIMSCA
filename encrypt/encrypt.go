package encrypt

import (
	"DIMSCA/config"
	"DIMSCA/pkg"
	"errors"
)

func GenCA() (string, string, int64, error) {

	if config.ConfCa.KeyPair.Algorithm == pkg.RSA {
		return GenRsa()
	} else if config.ConfCa.KeyPair.Algorithm == pkg.SM2 {
		return GenSm2()
	} else {
		return "", "", 0, errors.New("ca algo error")
	}
}
