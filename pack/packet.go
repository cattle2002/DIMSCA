package pack

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/wumansgy/goEncrypt/des"
)

type CoreServerCmd string

var Limit CoreServerCmd = "Lin"

func Packet(b []byte) ([]byte, error) {
	headerBytes := []byte("GDMP")
	// 消息编码base64
	if len(b) <= 1000 {
		eb, err := des.DesCbcEncrypt(b, []byte("12345678"), []byte("00000000"))
		if err != nil {
			return nil, err
		}
		esb := base64.StdEncoding.EncodeToString(eb)
		dataLenBytes := []byte(FormatNumberString(strconv.Itoa(len(esb))))
		newBytes := append(headerBytes, dataLenBytes...)
		newBytes = append(newBytes, []byte(esb)...)
		return newBytes, nil
	} else {
		//todo 上传到文件服务器
	}
	return nil, nil
}
func UPacket(b []byte) ([]byte, error) {
	if len(b) < 8 {
		return nil, errors.New("message not intact") //消息不完整
	}
	dataLenBytes := b[4:8]
	dateLen, err2 := strconv.Atoi(string(dataLenBytes))
	if err2 != nil {
		return nil, err2
	}
	db := b[8:]
	if len(db) != dateLen {
		return nil, errors.New("消息长度错误")
	}
	decode, err2 := base64.StdEncoding.DecodeString(string(db))
	if err2 != nil {
		return nil, errors.New(" base64.StdEncoding.DecodeString error ")
	}
	rs, err := des.DesCbcDecrypt(decode, []byte("12345678"), []byte("00000000"))
	if err != nil {
		return nil, errors.New("des.DesCbcDecrypt error ")
	}
	return rs, nil
}
func FormatNumberString(input string) string {
	if len(input) < 4 {
		// 在首部添加 '0'，直到字符串长度达到 3
		for len(input) < 4 {
			input = "0" + input
		}
	}
	return input
}

func ExtractCmdValue(jsonStr string) (string, error) {
	// 创建一个空的map来存储解析后的JSON数据
	var data map[string]interface{}
	// 解析JSON字符串
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return "", err
	}
	// 获取Command字段的值
	cmdValue, ok := data["Cmd"].(string)
	if !ok {
		//fmt.Printf("the command value is not string : %s", err.Error())
		return "", fmt.Errorf("cmd的值不是字符串类型")
	}
	return cmdValue, nil
}

//func UnMarshalToStruct(b []byte) (interface{}, error) {
//
//	var loginRes = protocol.LoginRet
//
//	//var limitReq = protocol.Limit
//
//	v, e := ExtractCmdValue(string(b))
//	//fmt.Println(string(b))
//	if e != nil {
//		return nil, e
//	} else {
//		switch v {
//		case LimitRet:
//			err := json.Unmarshal(b, &limitRes)
//			if err != nil {
//				return nil, err
//			}
//			return &limitRes, nil
//		}
//	}
//	return nil, nil
//}
