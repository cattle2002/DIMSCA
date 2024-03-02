package main

import "C"
import (
	"DIMSCA/encrypt"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/wenzhenxi/gorsa"
	"time"
)

func RsaGrantPermission_test() {
	p, s, _, err := encrypt.GenRsa()
	if err != nil {
		panic(err)
	}
	var ptbsc PTBSC
	ptbsc.CAAlgoType = "rsa"
	ptbsc.TimeStamp = time.Now().UnixMilli()
	ptbsc.Pwd = "12345678"
	ptbsc.Buyer = "zgw"
	ptbsc.Seller = "gzw"
	ptbsc.ContentMD5 = "12344"
	marshal, err := json.Marshal(ptbsc)
	if err != nil {
		panic(err)
	}
	ctr := GrantPermissionSign(C.CString(p), C.CString(string(marshal)))
	//fmt.Println(C.GoString(ctr))
	verify := GrantPermissionSignVerify(C.CString(s), ctr, C.CString("rsa"))
	decodeString, err := base64.StdEncoding.DecodeString(C.GoString(verify))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decodeString))
}
func Sm2GrantPermission_test() {
	p, s, _, err := encrypt.GenSm2()
	if err != nil {
		panic(err)
	}
	var ptbsc PTBSC
	ptbsc.CAAlgoType = "sm2"
	ptbsc.TimeStamp = time.Now().UnixMilli()
	ptbsc.Pwd = "12345678"
	ptbsc.Buyer = "zgw"
	ptbsc.Seller = "gzw"
	ptbsc.ContentMD5 = "12344"
	marshal, err := json.Marshal(ptbsc)
	if err != nil {
		panic(err)
	}
	ctr := GrantPermissionSign(C.CString(p), C.CString(string(marshal)))
	//fmt.Println(C.GoString(ctr))
	verify := GrantPermissionSignVerify(C.CString(s), ctr, C.CString("sm2"))
	decodeString, err := base64.StdEncoding.DecodeString(C.GoString(verify))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decodeString))
}
func RsaConfirmPermission_test() {
	p, s, _, err := encrypt.GenRsa()
	if err != nil {
		panic(err)
	}
	var ptbsc PTBSC
	ptbsc.CAAlgoType = "rsa"
	ptbsc.TimeStamp = time.Now().UnixMilli()
	ptbsc.Pwd = "12345678"
	ptbsc.Buyer = "zgw"
	ptbsc.Seller = "gzw"
	ptbsc.ContentMD5 = "12344"
	marshal, err := json.Marshal(ptbsc)
	if err != nil {
		panic(err)
	}

	c := ConfirmSign(C.CString(s), C.CString(string(marshal)), C.CString("rsa"), C.CString("1"))
	fmt.Println(C.GoString(c))
	c2 := ConfirmVerify(C.CString(p), c, C.CString("rsa"))
	fmt.Println(C.GoString(c2))
}
func Sm2ConfirmPermission_test() {
	p, s, _, err := encrypt.GenSm2()
	if err != nil {
		panic(err)
	}
	var ptbsc PTBSC
	ptbsc.CAAlgoType = "sm2"
	ptbsc.TimeStamp = time.Now().UnixMilli()
	ptbsc.Pwd = "12345678"
	ptbsc.Buyer = "zgw"
	ptbsc.Seller = "gzw"
	ptbsc.ContentMD5 = "12344"
	marshal, err := json.Marshal(ptbsc)
	if err != nil {
		panic(err)
	}

	c := ConfirmSign(C.CString(s), C.CString(string(marshal)), C.CString("sm2"), C.CString("3132333435363738"))
	fmt.Println(C.GoString(c))
	c2 := ConfirmVerify(C.CString(p), c, C.CString("sm2"))
	fmt.Println(C.GoString(c2))
}
func AesSymmtricKeyEncryptPlus_test() {
	// data := []byte("1234")
	// C.CString("1234")
	c := SymmtricKeyEncrypt_plus(C.CString("1234x*"), 4, C.CString("31323334353637383132333435363738"), C.CString("aes"))
	fmt.Println("----")
	dc := SymmtricKeyDecrypt_plus(c, C.CString("31323334353637383132333435363738"), C.CString("aes"))
	//fmt.Println(C.GoString(dc))
	fmt.Println(base64.StdEncoding.DecodeString(C.GoString(dc)))
}
func Sm4SymmtricKeyEncryptPlus_test() {
	// data := []byte("1234")
	// C.CString("1234")
	c := SymmtricKeyEncrypt_plus(C.CString("1234\n"), 5, C.CString("31323334353637383132333435363738"), C.CString("sm4"))
	//fmt.Println("----")
	dc := SymmtricKeyDecrypt_plus(c, C.CString("31323334353637383132333435363738"), C.CString("sm4"))
	//fmt.Println(C.GoString(dc))
	decodeString, err := base64.StdEncoding.DecodeString(C.GoString(dc))
	fmt.Println(len(decodeString), err)
}
func AsymmetricEncryptDoubleSign_test() {
	p1, s1, _, err := encrypt.GenRsa()
	if err != nil {
		panic(err)
	}
	p2, s2, _, err := encrypt.GenRsa()
	if err != nil {
		panic(err)
	}
	var ptbsc PTBSC
	ptbsc.CAAlgoType = "rsa"
	ptbsc.TimeStamp = time.Now().UnixMilli()
	ptbsc.Pwd = "12345678"
	ptbsc.Buyer = "zgw"
	ptbsc.Seller = "gzw"
	ptbsc.ContentMD5 = "12344"
	ptbscStr, err := json.Marshal(ptbsc)
	if err != nil {
		panic(err)
	}
	estr := AsymmetricEncryptDoubleSign(C.CString(p1), C.CString(s2), C.CString(string(ptbscStr)), C.CString("rsa"), C.CString("rsa"), C.CString("pwd"))
	var double DoubleStruct
	decodeString, err := base64.StdEncoding.DecodeString(C.GoString(estr))
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(decodeString, &double)
	if err != nil {

		panic(err)
	}
	fmt.Println(double.PubKeyEncryptJson)
	fmt.Println(len(double.PubKeyEncryptJson))

	keyEncrypt, err := gorsa.PriKeyDecrypt(double.PubKeyEncryptJson, s1)
	if err != nil {
		panic(err)
	}
	fmt.Println("--", keyEncrypt)
	//fmt.Println("SignDate:", double.PrivateKeyJsonSignData)
	err = gorsa.VerifySignSha256WithRsa(double.PubKeyEncryptJson, double.PrivateKeyJsonSignData, p2)
	fmt.Println(err)
}
func te() {
	//s := "7468555a48642f6b3075504a6479654e66546a3666464b7444746c376f6779356f6e6b51652f4e366249766144626c76456d3879314442517650786979442b52335272655771772b356c32794532743075684232717\n64b4975705654492b46364377326238616e6a4237472f746f2b7a7453304a6e564155517a59726b4f786a56556d7257336b377676383037654d6f573076595679374a773478614d6d56414a4953743855767a305831352f68332b4e65434556323430785039512f71765256\n4d76474d48684d496e67556d6b3058666f664e3153545344657a724c62754a2b34535058536c436e716177566b312f456261526c7966784146507a5241693761306b6142775352726d316f4e59504b44524d4368535969383163586d52362f334b36476131477a4a57534c78743736386142447566766c493434625061415a416e736a71336564336b497559696e476f33645646413d3d"
	s := "69446c71344b4b5461726f75564778783834496d5461686e56546d416161475048487753492f4d452f4a50593468396854346e4b4d594d7542623551754d2b4b58674a3447647a5833654e523077493866444753746a615452676947614a35684c497a486371536f6c6b393646496c746b613170674171746f74674e626f322b39666d414d496d57616b424b47764336394977635947626b567a387352685159686c6b62763272675444753933754876625772307477464a6e5832657750514b5378422f335054344643475a785637743239316d6452533459735a70546a2f516d3141594277334c576d52744c754337354868577175665a56314d777634667050467270354f597043785954676c4b42574630796d4f4d4b7768717a7665716d654864556856516b4c432b5471354e495a6d55352f334e63303942524654483273336f683045722f30695a73634f306e7a6c7a7175773d3d"
	_, err := hex.DecodeString(s)
	fmt.Println(err)
}
func plat_test() {
	var ca PlatformCA
	ca1 := GenPlatformCA(C.CString("rsa"), C.CString("3132333435363738"))
	err := json.Unmarshal([]byte(C.GoString(ca1)), &ca)
	if err != nil {
		panic(err)
	}
	//fmt.Println(ca.Publickey)
	//fmt.Println(ca.PrivateKey)
	//fmt.Println(ca.TimeStamp)
	confirm := PlatformConfirm(C.CString("rsa"), C.CString(ca.PrivateKey), C.CString("12345678"), C.CString("3132333435363738"))
	toString := base64.StdEncoding.EncodeToString([]byte("12345678"))
	grant := PlatformGrant(C.CString("rsa"), C.CString(ca.Publickey), C.CString(toString), confirm)
	fmt.Println(C.GoString(grant))
}

func main() {
	// RsaGrantPermission_test()
	// Sm2GrantPermission_test()
	//RsaConfirmPermission_test()
	//Sm2ConfirmPermission_test()
	//AesSymmtricKeyEncryptPlus_test()
	//Sm4SymmtricKeyEncryptPlus_test()
	//AsymmetricEncryptDoubleSign_test()
	//te()
	plat_test()
}
