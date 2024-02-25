package encrypt

import (
	"testing"
)

func TestSm4(t *testing.T) {

	b, err := Sm4Encyrpt([]byte("1234567812345678"), []byte("0001x\b*2"))
	if err != nil {
		t.Error(err)
	}
	t.Log(string(b), len(b))
	b2, err := Sm4Decrypt([]byte("1234567812345678"), b)
	if err != nil {
		t.Error(err)
	}
	t.Fatal(string(b2), len(b))
}
