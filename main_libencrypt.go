package main

import "C"
import (
	"DIMSCA/encrypt"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/wenzhenxi/gorsa"
	"github.com/wumansgy/goEncrypt/aes"
	"unsafe"
)

//export  GensymmetricKey
func GensymmetricKey() *C.char {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	toString := hex.EncodeToString(key)
	return C.CString(toString)
}

//export  SymmetricKeyEncrypt
func SymmetricKeyEncrypt(data *C.char, size C.int, key *C.char, algo *C.char) *C.char {
	gdata := C.GoBytes(unsafe.Pointer(data), size)
	gkey, err := hex.DecodeString(C.GoString(key))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	cipherText, err := aes.AesCbcEncrypt(gdata, gkey, []byte("0000000000000000"))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	s := base64.StdEncoding.EncodeToString(cipherText)
	return C.CString(s)
}

//export SymmetricKeyDecrypt
func SymmetricKeyDecrypt(data *C.char, algo *C.char, key *C.char) *C.char {
	gdata := C.GoString(data)
	gkey, err := hex.DecodeString(C.GoString(key))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	xdata, err := base64.StdEncoding.DecodeString(gdata)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	plainText, err := aes.AesCbcDecrypt(xdata, gkey, []byte("0000000000000000"))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:" + err.Error())
	}
	s := base64.StdEncoding.EncodeToString(plainText)
	return C.CString(s)
}

type PlatformCA struct {
	Publickey  string `json:"Publickey"`
	PrivateKey string `json:"PrivateKey"`
	TimeStamp  int64  `json:"TimeStamp"`
}

//export    GenPlatformCA
func GenPlatformCA(algo *C.char, hexStoreKey *C.char) *C.char {
	galgo := C.GoString(algo)
	if galgo != "sm2" && galgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:only support rsa and sm2")
	}
	ghexStoreKey := C.GoString(hexStoreKey)
	var pca PlatformCA
	if galgo == "sm2" {
		pk, sk, timeStamp, err := encrypt.GenSm2C(ghexStoreKey)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:GenSm2 error:%s" + err.Error())
		}
		pca.Publickey = pk
		pca.PrivateKey = sk
		pca.TimeStamp = timeStamp
		marshal, err := json.Marshal(pca)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:GenSm2 error:%s" + err.Error())
		}
		return C.CString(string(marshal))
	}
	pk, sk, timeStamp, err := encrypt.GenRsa()
	if err != nil {
		return C.CString("DIMSCASO-ERROR:GenRsa error:%s" + err.Error())
	}
	pca.Publickey = pk
	pca.PrivateKey = sk
	pca.TimeStamp = timeStamp
	marshal, err := json.Marshal(pca)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:GenRsa error:%s" + err.Error())
	}
	return C.CString(string(marshal))
}

// (平台授权)公钥加密

//export  PlatGrant
func PlatGrant(algo *C.char, platPublicKey *C.char, msgB64 *C.char) *C.char {
	galgo := C.GoString(algo)
	gplatPublicKey := C.GoString(platPublicKey)
	gmsg := C.GoString(msgB64)
	mmsg, err := base64.StdEncoding.DecodeString(gmsg)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:base64 decode error:%s" + err.Error())
	}
	if galgo != "sm2" && galgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:only support rsa and sm2")
	}
	if galgo == "sm2" {
		sm2Encrypt, err := encrypt.Sm2Encrypt(gplatPublicKey, mmsg)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2Encrypt error:%s" + err.Error())
		}
		return C.CString(sm2Encrypt)
	}
	publicEncrypt, err := gorsa.PublicEncrypt(string(mmsg), gplatPublicKey)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:RsaEncrypt error:%s" + err.Error())
	}
	return C.CString(publicEncrypt)
}

// PlatConfirm (平台授权)私钥解密加密

//export  PlatConfirm
func PlatConfirm(algo *C.char, platPrivateKey *C.char, cipherMsg *C.char, hexKeyStore *C.char) *C.char {
	galgo := C.GoString(algo)
	gplatPrivateKey := C.GoString(platPrivateKey)
	gcipherMsg := C.GoString(cipherMsg)
	ghexKeyStore := C.GoString(hexKeyStore)

	if galgo != "sm2" && galgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:only support rsa and sm2")
	}
	if galgo == "sm2" {
		tmpKey, err := hex.DecodeString(ghexKeyStore)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:hex decode error")
		}
		if len(tmpKey) != 8 {
			return C.CString("DIMSCASO-ERROR:key is 8byte")
		}
		sm2Decrypt, err := encrypt.Sm2DecryptC(gplatPrivateKey, []byte(gcipherMsg), ghexKeyStore)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2Encrypt error:%s" + err.Error())
		}
		return C.CString(sm2Decrypt)
	}
	decrypt, err := gorsa.PriKeyDecrypt(gcipherMsg, gplatPrivateKey)
	if err != nil {
		return C.CString("DIMSCASO-ERROR: gorsa.PriKeyDecrypt error:%s" + err.Error())
	}
	toString := base64.StdEncoding.EncodeToString([]byte(decrypt))
	return C.CString(toString)
}

//export  AsymmetricKeyEncrypt
func AsymmetricKeyEncrypt(pk *C.char, algo *C.char, symmetricKey *C.char) *C.char {
	gpk := C.GoString(pk)
	galgo := C.GoString(algo)
	gsymmetricKey := C.GoString(symmetricKey)
	if galgo != "sm2" && galgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:only support rsa and sm2")
	}
	if galgo == "sm2" {
		sm2Encrypt, err := encrypt.Sm2Encrypt(gpk, []byte(gsymmetricKey))
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2Encrypt error:%s" + err.Error())
		}
		return C.CString(sm2Encrypt)
	}
	publicEncrypt, err := gorsa.PublicEncrypt(gsymmetricKey, gpk)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:RsaEncrypt error:%s" + err.Error())
	}
	return C.CString(publicEncrypt)
}
func main() {}

//go build  -o  libencrypt.dll   -buildmode=c-shared  main_libencrypt.go
//go build  -o  libencrypt.so   -buildmode=c-shared  main_libencrypt.go
