package handle

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/protocol"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"strconv"
)

func CertInputResponseError(data string) {
	var res protocol.CertInputRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FErrorCode
	res.Cmd = string(CertInputRet)
	res.Msg = data
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}
func CertInputResponseSuccess() {
	var res protocol.CertInputRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FSuccessCode
	res.Cmd = string(CertInputRet)
	res.Msg = protocol.FSuccessMsg
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}
func CertRemakeResponseSuccess() {
	var res protocol.CertRemakeResX
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FSuccessCode
	res.Cmd = string(CertRemakeRet)
	res.Msg = protocol.FSuccessMsg
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}
func CertSyncResponseSuccess() {
	var res protocol.CertSyncRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FSuccessCode
	res.Cmd = string(CertSyncRet)
	res.Msg = protocol.FSuccessMsg
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}

func CertShowResponseError(errMsg string) {
	var res protocol.CertShowRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FErrorCode
	res.Cmd = string(CertShowRet)
	res.Msg = errMsg
	res.Msg = protocol.FSuccessMsg
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}

func CertOwnerResponseError(errMsg string) {
	var res protocol.CertOwnerRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FErrorCode
	res.Cmd = string(CertOwnerRet)
	res.Msg = errMsg
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager :%s", string(marshal))
}
func CertOwnerResponseSuccess(pk string, sk string) {
	var res protocol.CertOwnerRes
	res.IpAddr = config.ConfCa.Local.EthHost
	res.Code = protocol.FSuccessCode
	res.Cmd = string(CertOwnerRet)
	res.Msg = protocol.FSuccessMsg
	res.PublicKey = pk
	res.PrivateKey = sk
	marshal, _ := json.Marshal(res)
	err := ManagerConn.WriteMessage(websocket.TextMessage, marshal)
	if err != nil {
		log.Logger.Errorf("return msg to manager error:%s", err.Error())
		return
	}
	log.Logger.Tracef("return msg to manager:%s", string(marshal))
}

type CertListResPayload struct {
	User      string `json:"User"`
	PublicKey string `json:"PublicKey"`
}
type CertListRes struct {
	Code int                   `json:"Code"`
	Msg  string                `json:"Msg"`
	Data *[]CertListResPayload `json:"Data"`
}

func CertShowHandle() {
	url := fmt.Sprintf("http://127.0.0.1:%s/api/v1/cert/user/list", strconv.Itoa(config.ConfCa.Local.Port))
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		log.Logger.Errorf("http  post userlist error:%s", err.Error())
		return
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Logger.Errorf("http post userlist body readAll error:%s", err.Error())
		return
	}
	var list CertListRes
	err = json.Unmarshal(all, &list)
	if err != nil {
		log.Logger.Errorf("json  unmarshal certListRes  error:%s", err.Error())
		return
	}
	var resx protocol.CertShowRes
	if list.Code != protocol.FSuccessCode {
		resx.IpAddr = config.ConfCa.Local.EthHost
		resx.Code = protocol.FErrorCode
		resx.Cmd = string(CertShowRet)
		resx.Msg = list.Msg
		marshal, _ := json.Marshal(resx)
		err = ManagerConn.WriteMessage(websocket.TextMessage, marshal)
		if err != nil {
			log.Logger.Errorf("return msg to manager error:%s", err.Error())
			return
		}
	} else {
		resx.IpAddr = config.ConfCa.Local.EthHost
		resx.Cmd = string(CertShowRet)
		resx.Code = protocol.FSuccessCode
		resx.Msg = protocol.FSuccessMsg
		i := convert(*list.Data)
		resx.Data = *i
		marshal, _ := json.Marshal(resx)
		err = ManagerConn.WriteMessage(websocket.TextMessage, marshal)
		if err != nil {
			log.Logger.Errorf("return msg to manager error:%s", err.Error())
			return
		}
	}
}
func convert(cls []CertListResPayload) *[]protocol.CertShowResPayload {
	var csl []protocol.CertShowResPayload
	for i := 0; i < len(cls); i++ {
		var ele protocol.CertShowResPayload
		ele.User = cls[i].User
		ele.PublicKey = cls[i].PublicKey
		csl = append(csl, ele)
	}
	return &csl
}
func CertOwnerHandle() {
	//获取当前目录下的公钥和私钥
	sk, err := config.GetPrivateKeyPem()
	if err != nil {
		CertOwnerResponseError(err.Error())
	}
	pk, err := config.GetPublicKeyPem()
	if err != nil {
		CertOwnerResponseError(err.Error())
	}
	CertOwnerResponseSuccess(pk, sk)
}
