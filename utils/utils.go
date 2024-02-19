package utils

import (
	//"DIMSCA/config"
	"DIMSCA/log"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"
)

func MsgID() int64 {
	// 设置随机数种子，以确保每次运行生成不同的随机数序列
	intn := rand.Intn(500)
	// 生成 100 到 1000 之间的随机整数
	randomNumber := intn + 500 // 生成 0 到 900 的随机整数再加上 100

	return int64(randomNumber)
}

// WritePem pkPos  skPos 请写绝对路径
func WritePem(pk string, sk string, pkPos string, skPos string) error {

	_, err1 := os.Stat(pkPos)

	_, err2 := os.Stat(skPos)
	if err1 == nil && err2 == nil {
		pkPem, _ := os.ReadFile(pkPos)
		skPem, _ := os.ReadFile(skPos)
		pkPemMd5 := Md5(pkPem)
		skPemMd5 := Md5(skPem)
		pkMd5 := Md5([]byte(pk))
		skMd5 := Md5([]byte(sk))
		if pkPemMd5 == pkMd5 && skPemMd5 == skMd5 {
			log.Logger.Info("密钥对一样，无需重新写入文件")
			return nil
		} else {
			log.Logger.Info("密钥对不一致,来自从机解密获取真实私钥")
			pkC, err := os.Create(pkPos)
			if err != nil {
				return err
			}
			skC, err := os.Create(skPos)
			if err != nil {
				return err
			}
			pkReader := strings.NewReader(pk)
			skReader := strings.NewReader(sk)
			io.Copy(pkC, pkReader)
			io.Copy(skC, skReader)
			return nil
		}
	} else {
		pkC, err := os.Create(pkPos)
		if err != nil {
			return err
		}
		skC, err := os.Create(skPos)
		if err != nil {
			return err
		}
		pkReader := strings.NewReader(pk)
		skReader := strings.NewReader(sk)
		io.Copy(pkC, pkReader)
		io.Copy(skC, skReader)
		return nil
	}

}

// 将配置文件里面的身份改成Master / Slave
//func UpdateConfig(confPos string, identity string) error {
//	var c config.Config
//
//	file, err := os.ReadFile(confPos)
//	if err != nil {
//		log.Logger.Errorf("读取配置文件错误:%s", err.Error())
//		return err
//	}
//	err = json.Unmarshal(file, &c)
//	c.Local.IDentity = identity
//	indent, err := json.MarshalIndent(c, "", " ")
//	if err != nil {
//		log.Logger.Errorf("序列化配置文件错误:%s", err.Error())
//		return err
//	}
//	err = os.WriteFile(confPos, indent, 0666)
//	if err != nil {
//		log.Logger.Errorf("序列化配置文件错误:%s", err.Error())
//		return err
//	}
//	return nil
//}

func Clear() {
	_, err := os.Stat("pubic.pub")
	if err == nil {
		os.Remove("public.pub")
	}
	_, err = os.Stat("private.key")
	if err == nil {
		os.Remove("private.key")
	}
	os.Remove("cert.db")
}
func Md5(data []byte) string {
	s := md5.Sum(data)
	toString := hex.EncodeToString(s[:])
	return toString
}

// DateFormat 将毫秒时间戳转成年月日时分秒
func DateFormat(timestamp int64) string {
	tm := time.UnixMilli(timestamp)
	return tm.Format("2006-01-02 15:04:05")
}
func IntToBytes(num uint32) []byte {
	byteData := make([]byte, 4)

	binary.LittleEndian.PutUint32(byteData, num)
	return byteData
}

// BytesToInt 将4字节表示的数据转换为uint32整数
func BytesToInt(byteData []byte) uint32 {
	return binary.LittleEndian.Uint32(byteData)
}

func Int16ToBytes(num uint16) []byte {
	byteData := make([]byte, 2)
	binary.LittleEndian.PutUint16(byteData, num)
	return byteData
}
func BytesToInt16(byteData []byte) uint16 {
	return binary.LittleEndian.Uint16(byteData)
}

func Int64ToBytes(num uint64) []byte {
	byteData := make([]byte, 8)
	binary.LittleEndian.PutUint64(byteData, num)
	return byteData
}
func BytesToInt64(byteData []byte) uint64 {
	return binary.LittleEndian.Uint64(byteData)
}
