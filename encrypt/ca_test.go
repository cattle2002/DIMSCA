package encrypt

import (
	"DIMSCA/utils"
	"encoding/base64"
	"testing"
)

func TestGenCA(t *testing.T) {
	ca, s, i, err := GenCA()
	if err != nil {
		t.Error(err)
	}
	date := utils.DateFormat(i)
	t.Logf("publicKey:%s\nprivateKey:%s\ndate:%s\ntimeStamp:%d", ca, s, date, i)
}
func TestSm2Encrypt(t *testing.T) {
	data := "hello world"
	p, s, _, err := GenCA()
	if err != nil {
		t.Error(err)
	}
	encrypt, err := Sm2Encrypt(p, []byte(data))
	if err != nil {
		t.Error(err)
	}
	decrypt, err := Sm2Decrypt(s, []byte(encrypt))
	if err != nil {
		t.Error(err)
	}
	decodeString, err := base64.StdEncoding.DecodeString(decrypt)
	if err != nil {
		return
	}
	t.Log(string(decodeString))
}
