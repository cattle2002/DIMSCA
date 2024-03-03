package main

import "C"
import (
	"DIMSCA/config"
	"DIMSCA/handle"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/pkg"
	"DIMSCA/service"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/wenzhenxi/gorsa"
	"github.com/wumansgy/goEncrypt/aes"
	"io"
	"net/http"
	"strconv"
	"time"
	"unsafe"
)

func IniChannel() {
	//utils.Clear()
	config.ConfigIDenUpdateCh = make(chan []byte, 10)
	handle.MsgBusCh = make(chan []byte, 10)
	handle.CertReMakeCh = make(chan []byte, 10)
	handle.CoreServerLoginRetCh = make(chan []byte, 10)
	handle.LoginMsgCh = make(chan []byte, 10)
	handle.CertGetToMasterRetCh = make(chan []byte, 10)
	handle.CertGetFromSlaveRetCh = make(chan []byte, 10)
	handle.CoreServerConnStatusChRunning = make(chan bool, 10)
	handle.CoreServerConnStatusChDaemon = make(chan bool, 10)
	handle.WsCAManager = make(chan bool, 10)
}

// go build  -o libca.dll  -buildmode=c-shared main.go
func main() {
}

//export CaRunning
func CaRunning() {
	IniChannel()
	// err := config.NewConfig("./lib/config.json")
	err := config.NewConfig(pkg.ConfigFileName)
	if err != nil {
		log.Logger.Errorf("new config error:%s", err.Error())
		return
	}
	log.NewLoggerG()
	model.NewCertFile()
	//
	handle.Connect()
	go handle.MonitorHandle()
	go handle.LoginSend()
	go handle.Bus()
	go handle.Daemon()
	go config.Update()
	go handle.HandleWsManager()
	http.HandleFunc("/api/v1/sk", service.PrivateKey)
	http.HandleFunc("/api/v1/pk", service.PublicKey)
	http.HandleFunc("/api/v1/websocket/1", service.CertManager)
	http.HandleFunc("/api/v1/cert/user/list", service.CertList)
	http.HandleFunc("/test", service.Test)
	err = http.ListenAndServe(config.ConfCa.Local.Host+":"+strconv.Itoa(config.ConfCa.Local.Port), nil)
	if err != nil {
		log.Logger.Errorf("running ca http server error:%s", err.Error())
		return
	}
	select {}

}

//export GrantPermission
func GrantPermission(pubPem *C.char, ptbscStr *C.char) *C.char {
	gpubPem := C.GoString(pubPem)
	gptbscStr := C.GoString(ptbscStr)

	encrypt, err := gorsa.PublicEncrypt(gptbscStr, gpubPem)
	if err != nil {
		return C.CString("DISMCASO-ERROR:PublicKey Encrypt Error:%s" + err.Error())
	}
	return C.CString(encrypt)
}

//export  ConfirmPermission
func ConfirmPermission(privPem *C.char, cipherptbscStr *C.char) *C.char {
	//确认权限 使用自己的私钥进行解密
	gprivPem := C.GoString(privPem)
	gcipherSymmetricKey := C.GoString(cipherptbscStr)
	encrypt, err := gorsa.PriKeyEncrypt(gcipherSymmetricKey, gprivPem)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:PriKeyDecrypt Error:%s" + err.Error())
	}
	return C.CString(encrypt)
}

//export GetUserPublicKeyLocal
func GetUserPublicKeyLocal(user *C.char) *C.char {
	guser := C.GoString(user)
	if guser == "" {
		return C.CString("DIMSCASO-ERROR:user is empty")
	}
	var req service.TmpPublicKeyRequest
	//var ress service.TmpPublicKeyResponse
	req.Username = guser
	msg, err := json.Marshal(req)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:json marshal msg error:%s" + err.Error())
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	url := "http://127.0.0.1:5517/api/v1/pk"
	reqc, err := http.NewRequest("POST", url, bytes.NewReader(msg))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:New Http Request Error:" + err.Error())
	}
	reqc.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(reqc)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Send Request Error:%s" + err.Error())
	}
	defer resp.Body.Close()
	b2, err := io.ReadAll(resp.Body)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Read Resp Body Error:" + err.Error())
	}
	return C.CString(string(b2))
}

//export  GetUserPrivateKeyLocalCa
func GetUserPrivateKeyLocalCa(user *C.char, password *C.char) *C.char {
	guser := C.GoString(user)
	gpassword := C.GoString(password)
	var req service.LocalRequest
	var res service.LocalResponse
	req.Username = guser
	req.Password = gpassword
	b, _ := json.Marshal(req)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	url := "http://127.0.0.1:5517/api/v1/sk"
	reqc, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return C.CString("DIMSCASO-ERROR:New Http Request Error:" + err.Error())
	}
	reqc.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(reqc)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Send Request Error:%s" + err.Error())
	}
	defer resp.Body.Close()
	b2, err := io.ReadAll(resp.Body)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Read Resp Body Error:" + err.Error())
	}
	err = json.Unmarshal(b2, &res)
	if err != nil {
		return C.CString("DIMSCASO-ERROR:Json Unmarshal Error:" + err.Error())
	}
	return C.CString(res.PrivateKey)
}

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

//export  AsymmetricEncryptDouble
func AsymmetricEncryptDouble(pk *C.char, sk *C.char, hexSymmetricKey *C.char) *C.char {
	gpk := C.GoString(pk)
	gsk := C.GoString(sk)
	ghexSymmtrickey := C.GoString(hexSymmetricKey)

	publicEncrypt, err := gorsa.PublicEncrypt(string(ghexSymmtrickey), gpk)
	if err != nil {
		return C.CString(fmt.Sprintf("DIMSCASO-ERROR:%s:%s", "public key encrypt error", err.Error()))
	}
	encrypt, err := gorsa.PriKeyEncrypt(publicEncrypt, gsk)
	if err != nil {
		return C.CString(fmt.Sprintf("DIMSCASO-ERROR:%s:%s", "private key encrypt error", err.Error()))
	}

	return C.CString(encrypt)
}

//export  AsymmetricDecryptDouble
func AsymmetricDecryptDouble(pk *C.char, sk *C.char, cipherHexSymmetricKey *C.char) *C.char {
	gpk := C.GoString(pk)
	gsk := C.GoString(sk)
	gcipherHexSymmetricKey := C.GoString(cipherHexSymmetricKey)

	decrypt, err := gorsa.PublicDecrypt(gcipherHexSymmetricKey, gpk)
	if err != nil {
		return C.CString(fmt.Sprintf("DIMSCASO-ERROR:%s:%s", "public key decrypt error", err.Error()))
	}
	publicDecrypt, err := gorsa.PriKeyDecrypt(decrypt, gsk)
	if err != nil {
		return C.CString(fmt.Sprintf("DIMSCASO-ERROR:%s:%s", "private key decrypt error", err.Error()))
	}
	toString := base64.StdEncoding.EncodeToString([]byte(publicDecrypt))
	return C.CString(toString)
}
