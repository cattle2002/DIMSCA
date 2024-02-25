package encrypt

import (
	"bytes"
	"errors"

	"github.com/tjfoc/gmsm/sm4"
)

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS5Padding(cipherText []byte) []byte {
	return PKCS7Padding(cipherText, 8)
}
func Unpadding(src []byte) []byte {
	n := len(src)
	if n == 0 {
		return src
	}
	paddingNum := int(src[n-1])
	return src[:n-paddingNum]
}

func Sm4Encyrpt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key length isnot 16 byte")
	}
	b, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b2 := PKCS7Padding(data, 16)
	dst := make([]byte, len(b2))
	b.Encrypt(dst, b2)
	return dst, nil
}

func Sm4Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key length isnot 16 byte")
	}
	b, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(data))
	b.Decrypt(dst, data)
	b2 := Unpadding(dst)
	return b2, nil
}
