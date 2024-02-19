package handle

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/pkg"
	"DIMSCA/protocol"
	"DIMSCA/utils"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/wenzhenxi/gorsa"
	"strconv"
)

// certGetFromSlaveReqInstructor 创建从证书的证书请求(发送获取加密私钥的请求)
func certGetFromSlaveReqInstructor() {
	var req protocol.CertGetFromSlaveReq
	req.Cmd = string(protocol.CertFromSlave)
	req.Program = string(protocol.Program)
	req.Payload.ID = utils.MsgID()
	req.Payload.Username = config.ConfCa.Local.User
	req.Payload.PublicAlgoType = config.ConfCa.KeyPair.Algorithm
	req.Payload.PublicKey = pkg.LoginPk
	marshal, _ := json.Marshal(req)
	SSendMsg(marshal)
}

func certGetToMasterRet() (*protocol.CertGetToMasterRets, error) {
	v := <-CertGetToMasterRetCh
	var req protocol.CertGetToMasterRets
	err := json.Unmarshal(v, &req)
	if err != nil {
		return nil, err
	}
	return &req, nil

}
func CertGetFromSlaveRetHandle() error {
	//todo 判断当前身份是否已经确定
	var req protocol.CertGetFromSlaveRes
	if config.ConfCa.Local.IDentity == "" {
		return errors.New("机器身份没有确认")
	}
	v := <-CertGetFromSlaveRetCh
	err := json.Unmarshal(v, &req)
	if err != nil {
		log.Logger.Errorf("反序列化失败:%s", err.Error())
		return err
	}

	//todo 读取当前公钥和私钥
	skPem, err := utils.GetPrivateKeyPem(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PrivateKeyPath)
	if err != nil {
		log.Logger.Errorf("读取私钥文件失败:%s", err.Error())
		return err
	}
	//todo 使用Rsa公钥类型然后进行加密,
	if req.Payload.PublicKeyAgoType == config.ConfCa.KeyPair.Algorithm {
		cipherPrivateKey, err := gorsa.PublicEncrypt(skPem, req.Payload.PublicKey)
		if err != nil {
			log.Logger.Errorf("Rsa 公钥加密失败:%s", err.Error())
			return err
		}
		pem, err := utils.GetPublicKeyPem(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PublicKeyPath)
		if err != nil {
			return err
		}
		ca, err := model.FindLastCA(config.ConfCa.Local.User)
		if err != nil {
			return err
		}

		instructor := certGetFromSlaveRetInstructor(req.Payload.ID, cipherPrivateKey, protocol.SuccessCode, pem, ca.TimeStamp)
		//todo 这个是个问题,报文没有加密就走过去了
		log.Logger.Errorf("write:%s", string(instructor))
		err = CoreServerConn.WriteMessage(websocket.TextMessage, instructor)
		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("协议尚未支持")
	}

}
func certGetFromSlaveRetInstructor(id int64, cipherPrivateKey string, retCode int, publicKey string, timeStamp int64) []byte {
	var res protocol.CertGetFromSlaveRet
	res.Cmd = string(protocol.GetCertForSlaveRet)
	res.Program = string(protocol.Program)
	res.RetCode = retCode
	res.Payload.ID = id
	res.Payload.CipherPrivateKey = cipherPrivateKey
	//publicKey =  p
	formatInt64 := strconv.FormatInt(timeStamp, 10)
	publicKey = publicKey + formatInt64
	res.Payload.PublicKey = publicKey
	res.Payload.TimeStamp = timeStamp
	marshal, _ := json.Marshal(res)
	return marshal
}
