package main

import "C"
import (
	"DIMSCA/config"
	"DIMSCA/encrypt"
	"DIMSCA/pkg"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unsafe"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/wenzhenxi/gorsa"
	"github.com/wumansgy/goEncrypt/aes"
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

type PTBSC struct {
	Pwd        string `json:"Pwd"`
	TimeStamp  int64  `json:"TimeStamp"`
	Buyer      string `json:"Buyer"`
	Seller     string `json:"Seller"`
	ContentMD5 string `json:"ContentMD5"`
	CAAlgoType string ` json:"CAAlgoType"`
}
type PTBSCSign struct {
	Pwd        string `json:"Pwd"`
	TimeStamp  int64  `json:"TimeStamp"`
	Buyer      string `json:"Buyer"`
	Seller     string `json:"Seller"`
	ContentMD5 string `json:"ContentMD5"`
	CAAlgoType string ` json:"CAAlgoType"`
	SignData   string `json:"SignData"`
}

func Sm2Encrypt(pk string, data []byte) (string, error) {
	publicKey, err := x509.ReadPublicKeyFromPem([]byte(pk))
	if err != nil {
		return "", err
	}
	encryptText, err := sm2.Encrypt(publicKey, data, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return "", err
	} else {
		toString := hex.EncodeToString(encryptText)
		return toString, nil
	}
}

// 这个函数只涉及到公钥加密,不需要私钥签名
func GrantPermissionSign(pubPem *C.char, ptbscStr *C.char) *C.char {
	var ptbsc PTBSC
	gpubPem := C.GoString(pubPem)
	gptbscStr := C.GoString(ptbscStr)
	//fmt.Println(gptbscStr)
	err := json.Unmarshal([]byte(gptbscStr), &ptbsc)
	if err != nil {
		return C.CString("DISMCASO-ERROR:JsonUnmarshal Pwd error:%s" + err.Error())
	}
	lower := strings.ToLower(ptbsc.CAAlgoType)
	if lower != "sm2" && lower != "rsa" {
		return C.CString("DISMCASO-ERROR:CAAlgoType Error")
	}

	if lower == "sm2" {
		sm2Encrypt, err := encrypt.Sm2Encrypt(gpubPem, []byte(gptbscStr))
		if err != nil {
			return C.CString("DISMCASO-ERROR:Sm2Encrypt Error:%s" + err.Error())
		}
		return C.CString(sm2Encrypt)
	}
	rsaEncrypt, err := gorsa.PublicEncrypt(gptbscStr, gpubPem)
	if err != nil {
		return C.CString("DISMCASO-ERROR:PublicKey Encrypt Error:%s" + err.Error())
	}
	return C.CString(rsaEncrypt)
}
func GrantPermissionSignVerify(privPem *C.char, cipherptbscStr *C.char, algo *C.char) *C.char {
	//var ptbsc PTBSC
	gprivPem := C.GoString(privPem)
	galgo := C.GoString(algo)
	gcipherptbscStr := C.GoString(cipherptbscStr)
	upper := strings.ToLower(galgo)
	if upper != "sm2" && upper != "rsa" {
		return C.CString("DISMCASO-ERROR:CAAlgoType Error")
	}
	if upper == "sm2" {

		decrypt, err := encrypt.Sm2Decrypt(gprivPem, []byte(gcipherptbscStr))
		if err != nil {
			return C.CString("DISMCASO-ERROR:Sm2Decrypt Error:%s" + err.Error())
		}
		return C.CString(decrypt)
	} else {
		decrypt, err := gorsa.PriKeyDecrypt(gcipherptbscStr, gprivPem)
		if err != nil {
			return C.CString("DISMCASO-ERROR:Rsa PrivateKey Decrypt Error:%s" + err.Error())
		}
		return C.CString(base64.StdEncoding.EncodeToString([]byte(decrypt)))
	}
}

func ConfirmSign(sk *C.char, ptbscStr *C.char, algo *C.char, key *C.char) *C.char {
	var ptbscSign PTBSCSign
	var ptbsc PTBSC
	gsk := C.GoString(sk)
	gptbscStr := C.GoString(ptbscStr)
	galgo := C.GoString(algo)
	gkey := C.GoString(key)
	err := json.Unmarshal([]byte(gptbscStr), &ptbsc)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Unmarshal ptbsc  error:%s" + err.Error())
	}
	lower := strings.ToLower(galgo)
	if lower != "sm2" && lower != "rsa" {
		return C.CString("DISMCASO-ERROR:Sign CAAlgoType Error")
	}

	if lower == "sm2" {
		decodeString, err := hex.DecodeString(gkey)
		if err != nil {
			return C.CString("DISMCASO-ERROR:Hex Decode error:%s" + err.Error())
		}
		if len(decodeString) != 8 {
			return C.CString("DIMSCASO-ERROR:Key is 8 byte")
		}
		sm2Sign, err := encrypt.Sm2Sign(gsk, gkey, []byte(gptbscStr))
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2 Sign error:%s" + err.Error())
		}
		ptbscSign.SignData = sm2Sign
		ptbscSign.Pwd = ptbsc.Pwd
		ptbscSign.TimeStamp = ptbsc.TimeStamp
		ptbscSign.Buyer = ptbsc.Buyer
		ptbscSign.Seller = ptbsc.Seller
		ptbscSign.ContentMD5 = ptbsc.ContentMD5
		ptbscSign.CAAlgoType = ptbsc.CAAlgoType
		ptbscSignData, err := json.Marshal(ptbscSign)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Json Marshal error:%s" + err.Error())
		}
		toString := base64.StdEncoding.EncodeToString(ptbscSignData)
		return C.CString(toString)
	}
	rsaSign, err := gorsa.SignSha256WithRsa(gptbscStr, gsk)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Rsa sign error:%s" + err.Error())
	}
	ptbscSign.SignData = rsaSign
	ptbscSign.Pwd = ptbsc.Pwd
	ptbscSign.TimeStamp = ptbsc.TimeStamp
	ptbscSign.Buyer = ptbsc.Buyer
	ptbscSign.Seller = ptbsc.Seller
	ptbscSign.ContentMD5 = ptbsc.ContentMD5
	ptbscSign.CAAlgoType = ptbsc.CAAlgoType
	ptbscSignData, err := json.Marshal(ptbscSign)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Marshal error:%s" + err.Error())
	}
	toString := base64.StdEncoding.EncodeToString(ptbscSignData)
	return C.CString(toString)
}
func ConfirmVerify(pk *C.char, ptbscSignData *C.char, algo *C.char) *C.char {
	var ptbscSign PTBSCSign
	var ptbsc PTBSC
	gpk := C.GoString(pk)
	gptbscSignData := C.GoString(ptbscSignData)
	galgo := C.GoString(algo)
	if strings.ToLower(galgo) != "sm2" && strings.ToLower(galgo) != "rsa" {
		return C.CString("DIMSCASO-ERROR:CAAlgoType Error")
	}
	if strings.ToLower(galgo) == "sm2" {
		decodeString, err := base64.StdEncoding.DecodeString(gptbscSignData)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Base64 Decode error:%s" + err.Error())
		}
		err = json.Unmarshal(decodeString, &ptbscSign)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Json Unmarshal ptbscSign error:%s" + err.Error())
		}
		ptbsc.Buyer = ptbscSign.Buyer
		ptbsc.Seller = ptbscSign.Seller
		ptbsc.ContentMD5 = ptbscSign.ContentMD5
		ptbsc.CAAlgoType = ptbscSign.CAAlgoType
		ptbsc.Pwd = ptbscSign.Pwd
		ptbsc.TimeStamp = ptbscSign.TimeStamp
		if galgo != ptbsc.CAAlgoType {
			return C.CString("DIMSCASO-Error:Algo not match")
		}
		b, err := json.Marshal(ptbsc)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Json Marshal ptbsc error:%s" + err.Error())
		}

		err = encrypt.Sm2Verify(gpk, ptbscSign.SignData, string(b))
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2 Verify error:%s" + err.Error())
		} else {
			return C.CString("DIMSCASO-Success:Sm2 Verify success")
		}
	}
	decodeString, err := base64.StdEncoding.DecodeString(gptbscSignData)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Base64 Decode error:%s" + err.Error())
	}
	err = json.Unmarshal(decodeString, &ptbscSign)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Unmarshal ptbscSign error:%s" + err.Error())
	}
	ptbsc.Buyer = ptbscSign.Buyer
	ptbsc.Seller = ptbscSign.Seller
	ptbsc.ContentMD5 = ptbscSign.ContentMD5
	ptbsc.CAAlgoType = ptbscSign.CAAlgoType
	ptbsc.Pwd = ptbscSign.Pwd
	ptbsc.TimeStamp = ptbscSign.TimeStamp
	if galgo != ptbsc.CAAlgoType {
		return C.CString("DIMSCASO-Error:Algo not match")
	}
	b, err := json.Marshal(ptbsc)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Marshal ptbsc error:%s" + err.Error())
	}
	err = gorsa.VerifySignSha256WithRsa(string(b), ptbscSign.SignData, gpk)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Rsa Verify error:%s" + err.Error())
	} else {
		return C.CString("DIMSCASO-Success:Rsa Verify success")
	}
}

// aes   sm4
func SymmtricKeyEncrypt_plus(data *C.char, size C.int, key *C.char, algo *C.char) *C.char {
	gdata := C.GoBytes(unsafe.Pointer(data), size)
	gkey, err := hex.DecodeString(C.GoString(key))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Hex Decode error:%s" + err.Error())
	}
	galgo := C.GoString(algo)

	if len(gkey) != 16 {
		return C.CString("DIMSCASO-ERROR:SymmtricKeyEncrypt Algo Key only 16 byte ")
	}
	if strings.ToLower(galgo) != "aes" && strings.ToLower(galgo) != "sm4" {
		return C.CString("DIMSCASO-ERROR:SymmtricKeyEncrypt Algo support aes and  sm4 ")
	}
	if galgo == "aes" {
		cipherText, err := aes.AesCbcEncryptBase64(gdata, gkey, gkey)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:AesCbcEncryptBase64 error:%s" + err.Error())
		}

		return C.CString(cipherText)
	}
	b, err := encrypt.Sm4Encyrpt(gkey, gdata)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Sm4Encyrpt error:%s" + err.Error())
	} else {
		s := base64.StdEncoding.EncodeToString(b)
		return C.CString(s)
	}
}

func SymmtricKeyDecrypt_plus(cipherData *C.char, key *C.char, algo *C.char) *C.char {

	// gdata := C.GoBytes(unsafe.Pointer(cipherData), size)
	gdata := C.GoString(cipherData)
	gkey, err := hex.DecodeString(C.GoString(key))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Hex Decode error:%s" + err.Error())
	}
	galgo := C.GoString(algo)
	if len(gkey) != 16 {
		return C.CString("DIMSCASO-ERROR:SymmtricKeyDecrypt Algo Key only 16 byte ")
	}
	if strings.ToLower(galgo) != "aes" && strings.ToLower(galgo) != "sm4" {
		return C.CString("DIMSCASO-ERROR:SymmtricKeyDecrypt Algo support aes and  sm4 ")
	}
	if galgo == "aes" {
		cipherText, err := aes.AesCbcDecryptByBase64(string(gdata), gkey, gkey)
		if err != nil {
			return C.CString("DIMSCASO-ERROR: AesCbcDecryptByBase64 :%s" + err.Error())
		}
		s := base64.StdEncoding.EncodeToString(cipherText)
		return C.CString(s)
	}
	decodeString, err := base64.StdEncoding.DecodeString(gdata)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Base64 Decode error:%s" + err.Error())
	}
	b, err := encrypt.Sm4Decrypt(gkey, decodeString)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Sm4Decrypt:%s" + err.Error())
	} else {
		s := base64.StdEncoding.EncodeToString(b)
		return C.CString(s)
	}
}

type DoubleStruct struct {
	PubKeyEncryptJson      string `json:"PubKeyEncryptJson"`
	PrivateKeyJsonSignData string `json:"PrivateKeyJsonSignData"`
}

func AsymmetricEncryptDoubleSign(pk *C.char, sk *C.char, ptbscStr *C.char, pkAlgo *C.char, skAlgo *C.char, skStorePwd *C.char) *C.char {
	var doubleStruct DoubleStruct
	gpk := C.GoString(pk)
	gsk := C.GoString(sk)
	gptbscStr := C.GoString(ptbscStr)
	gpkAlgo := C.GoString(pkAlgo)
	gskAlgo := C.GoString(skAlgo)
	gskStorePwd := C.GoString(skStorePwd)

	//1.先使用公钥进行加密
	if gpkAlgo != "sm2" && gpkAlgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:public key algo only support rsa and sm2")
	}
	if gskAlgo != "sm2" && gskAlgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:public key algo only support rsa and sm2")
	}
	if gpkAlgo == "rsa" {
		s, err := gorsa.PublicEncrypt(gptbscStr, gpk)
		if err != nil {
			return C.CString("DIMSCASO-ERROR: gorsa.PublicEncrypt error:%s" + err.Error())
		}
		if gskAlgo == "rsa" {
			s2, err2 := gorsa.SignSha256WithRsa(s, gsk)
			if err2 != nil {
				return C.CString("DIMSCASO-ERROR: gorsa.SignSha256WithRsa error:%s" + err2.Error())
			}
			doubleStruct.PubKeyEncryptJson = s
			doubleStruct.PrivateKeyJsonSignData = s2
			b, err3 := json.Marshal(doubleStruct)
			if err3 != nil {
				return C.CString("DIMSCASO-ERROR:Json Marshal doubleStruct error:%s" + err3.Error())
			}
			s3 := base64.StdEncoding.EncodeToString(b)
			return C.CString(s3)
		}
		skStorePwdd, err := hex.DecodeString(gskStorePwd)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Hex Decode error:%s" + err.Error())
		}
		if len(skStorePwdd) != 8 {
			return C.CString("DIMSCASO-ERROR:Sk skStorePwdd only 8 byte")
		}
		s2, err2 := encrypt.Sm2Sign(gsk, gskStorePwd, []byte(s))
		if err2 != nil {
			return C.CString("DIMSCASO-ERROR:Sm2Sign error:%s" + err2.Error())
		}
		doubleStruct.PubKeyEncryptJson = s
		doubleStruct.PrivateKeyJsonSignData = s2
		b, err3 := json.Marshal(doubleStruct)
		if err3 != nil {
			return C.CString("DIMSCASO-ERROR:Json Marshal doubleStruct error:%s" + err3.Error())
		}
		s3 := base64.StdEncoding.EncodeToString(b)
		return C.CString(s3)
	}
	s, err2 := encrypt.Sm2Encrypt(gpk, []byte(gptbscStr))
	if err2 != nil {
		return C.CString("DIMSCASO-ERROR:Sm2Encrypt error:%s" + err2.Error())
	}
	if gskAlgo == "rsa" {
		s2, err2 := gorsa.SignSha256WithRsa(s, gsk)
		if err2 != nil {
			return C.CString("DIMSCASO-ERROR: gorsa.SignSha256WithRsa error:%s" + err2.Error())
		}
		doubleStruct.PubKeyEncryptJson = s
		doubleStruct.PrivateKeyJsonSignData = s2
		b, err3 := json.Marshal(doubleStruct)
		if err3 != nil {
			return C.CString("DIMSCASO-ERROR:Json Marshal doubleStruct error:%s" + err3.Error())
		}
		s3 := base64.StdEncoding.EncodeToString(b)
		return C.CString(s3)
	}
	s2, err2 := encrypt.Sm2Sign(gsk, gskStorePwd, []byte(s))
	if err2 != nil {
		return C.CString("DIMSCASO-ERROR:Sm2Sign error:%s" + err2.Error())
	}
	doubleStruct.PubKeyEncryptJson = s
	doubleStruct.PrivateKeyJsonSignData = s2
	b, err3 := json.Marshal(doubleStruct)
	if err3 != nil {
		return C.CString("DIMSCASO-ERROR:Json Marshal doubleStruct error:%s" + err3.Error())
	}
	s3 := base64.StdEncoding.EncodeToString(b)
	return C.CString(s3)
}

// todo 等待测试 解密动态库似乎有点问题

func AsymmetricDecryptDoubleSign(pk *C.char, sk *C.char, doubleStructStr *C.char, pkAlgo *C.char, skAlgo *C.char) *C.char {
	gpk := C.GoString(pk)
	gsk := C.GoString(sk)

	gdoubleStructStr := C.GoString(doubleStructStr)
	gpkAlgo := C.GoString(pkAlgo)
	gskAlgo := C.GoString(skAlgo)
	// gskStorePwd := C.GoString(skStorePwd)
	var doubleStruct DoubleStruct

	if gpkAlgo != "sm2" && gpkAlgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:public key algo only support rsa and sm2")
	}
	if gskAlgo != "sm2" && gskAlgo != "rsa" {
		return C.CString("DIMSCASO-ERROR:public key algo only support rsa and sm2")
	}
	b, err := base64.StdEncoding.DecodeString(gdoubleStructStr)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Base64 Decode error:%s" + err.Error())
	}
	err = json.Unmarshal(b, &doubleStruct)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Unmarshal doubleStruct error:%s" + err.Error())
	}
	//解密  doubleStruct里面的 PubKeyEncryptJson字段,分rsa和sm2两种算法,gpkalgo是签名的私钥算法类型
	if gskAlgo == "rsa" {

		s, err2 := gorsa.PriKeyDecrypt(gsk, doubleStruct.PubKeyEncryptJson)
		if err2 != nil {
			return C.CString("DIMSCASO-ERROR: gorsa.PriKeyDecrypt error:%s" + err2.Error())
		}
		//开始验签
		if gpkAlgo == "rsa" {
			err = gorsa.VerifySignSha256WithRsa(s, doubleStruct.PrivateKeyJsonSignData, gpk)
			if err != nil {
				return C.CString("DIMSCASO-ERROR: gorsa.VerifySignSha256WithRsa error:%s" + err.Error())
			}
			s2 := base64.StdEncoding.EncodeToString([]byte(s))
			return C.CString(s2)
		}
		err = encrypt.Sm2Verify(gpk, doubleStruct.PrivateKeyJsonSignData, s)
		if err != nil {
			return C.CString("DIMSCASO-ERROR:Sm2Verify error:%s" + err.Error())
		}
		s2 := base64.StdEncoding.EncodeToString([]byte(s))
		return C.CString(s2)
	}
	s, err2 := encrypt.Sm2Decrypt(gsk, []byte(doubleStruct.PubKeyEncryptJson))
	if err2 != nil {
		return C.CString("DIMSCASO-ERROR:Sm2Decrypt error:%s" + err2.Error())
	}
	if gpkAlgo == "rsa" {
		err = gorsa.VerifySignSha256WithRsa(s, doubleStruct.PrivateKeyJsonSignData, gpk)
		if err != nil {
			return C.CString("DIMSCASO-ERROR: gorsa.VerifySignSha256WithRsa error:%s" + err.Error())
		}
		s2 := base64.StdEncoding.EncodeToString([]byte(s))
		return C.CString(s2)
	}
	err = encrypt.Sm2Verify(gpk, doubleStruct.PrivateKeyJsonSignData, s)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Sm2Verify error:%s" + err.Error())
	}
	s2 := base64.StdEncoding.EncodeToString([]byte(s))
	return C.CString(s2)
}
