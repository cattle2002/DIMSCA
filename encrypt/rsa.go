package encrypt

import (
	"DIMSCA/config"
	"DIMSCA/utils"
	"fmt"
	"github.com/wenzhenxi/gorsa"
	"strconv"
	"strings"
	"time"
)

func GenRsa() (string, string, int64, error) {
	resp, err := gorsa.GenerateKey(config.ConfCa.KeyPair.Bits)
	if err != nil {
		return "", "", 0, err
	}
	return resp.PublicKeyBase64, resp.PrivateKeyBase64, time.Now().UnixMilli(), nil
}
func GenRsaWrapper(user string, kType string) *WrapKeyPair {
	resp, err := gorsa.GenerateKey(2048)
	if err != nil {
		panic(err)
	}
	pair := WrapKeyPair{
		PublicKey:  resp.PublicKeyBase64,
		PrivateKey: resp.PrivateKeyBase64,
		Issuer:     user,
		KeyType:    kType,
		TimeStamp:  time.Now().UnixMilli(),
	}
	return &pair
	//pair.EncodePublicKey(user, kType)
}

type WrapKeyPair struct {
	PublicKey  string
	PrivateKey string
	Issuer     string
	TimeStamp  int64
	KeyType    string
}

// 公私钥解析形式tlvv

func (w *WrapKeyPair) EncodePublicKey() string {
	if len(w.KeyType) != 2 {
		panic("kType length must be 2")
	}
	fmt.Println(len(w.PublicKey))
	//fmt.Println([]byte(w.PublicKey))
	KeyType := utils.Int16ToBytes(2)
	user := make([]byte, 0)
	user = append(user, []byte(w.Issuer)...)
	userLength := utils.Int16ToBytes(uint16(len(w.Issuer)))
	formatInt := strconv.FormatInt(w.TimeStamp, 10)
	bytesLength := utils.Int16ToBytes(uint16(len(formatInt)))
	replace := fmt.Sprintf("%s%s%s%s%s%s%s", utils.PkBegin(), string(KeyType), string(userLength), string(bytesLength), w.KeyType, w.Issuer, formatInt)
	// 替换公钥字符串中的开头标记
	s := strings.Replace(w.PublicKey, utils.PkBegin(), replace, 1)
	fmt.Println(len(s))
	fmt.Println(s)
	fmt.Println("解密前时间错:", w.TimeStamp)
	return s
}

func (w *WrapKeyPair) DeCodePublicKey(wrapperPub string) {
	begin := utils.PkBegin()
	wrapperPubByte := []byte(wrapperPub)
	kType := wrapperPubByte[len(begin) : len(begin)+2]
	bytesToInt16 := utils.BytesToInt16(kType)
	tp := wrapperPubByte[len(begin)+6 : len(begin)+6+int(bytesToInt16)]
	fmt.Println("密钥类型：", string(tp))
	userLenBytes := wrapperPubByte[len(begin)+2 : len(begin)+4]
	toInt16 := utils.BytesToInt16(userLenBytes)
	username := wrapperPubByte[len(begin)+6+2 : len(begin)+6+2+int(toInt16)]
	fmt.Println("用户名：", string(username))
	timeStampBytes := wrapperPubByte[len(begin)+4 : len(begin)+6]
	toInt64 := utils.BytesToInt16(timeStampBytes)
	timeStampX := wrapperPubByte[len(begin)+6+2+int(toInt16) : len(begin)+6+2+int(toInt16)+int(toInt64)]
	fmt.Println("时间错:", string(timeStampX))
}
func (w *WrapKeyPair) EncodePrivateKey() {

}
