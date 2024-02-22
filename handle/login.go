package handle

import (
	"DIMSCA/config"
	"DIMSCA/encrypt"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/pkg"
	"DIMSCA/protocol"
	"DIMSCA/utils"
	"encoding/json"
	"errors"
	"time"
)

func loginReqInstructor(timeStamp int64) []byte {
	var req protocol.LoginReq
	req.Cmd = string(protocol.Login)
	req.Program = string(protocol.Program)
	req.Payload.ID = utils.MsgID()
	req.Payload.PublicKey = pkg.LoginPk
	req.Payload.TimeStamp = timeStamp
	req.Payload.Username = config.ConfCa.Local.User
	req.Payload.Password = config.ConfCa.Local.Password
	req.Payload.PublicAlgoType = config.ConfCa.KeyPair.Algorithm
	marshal, _ := json.Marshal(req)
	return marshal
}
func login() error {
	//todo 第一步将配置文件里面的身份标识置为空
	err := config.UpdateIDentity("")
	if err != nil {
		log.Logger.Errorf("清楚配置文件身份失败:%s", err.Error())
		return err
	}
	cert, err := model.FindLastCA(config.ConfCa.Local.User)
	if err != nil {
		return err
	}
	if cert.ID == 0 {
		log.Logger.Trace("数据库没有用户密钥对,正在生成中...")
		//todo 创建临时公钥
		//todo 生成临时公私钥,保存到内存里面 只允许RSA
		pk, sk, now, err := encrypt.GenCA()
		if err != nil {
			return errors.New("生成公私钥失败")
		}
		pkg.LoginPk = pk
		pkg.LoginSk = sk
		pkg.CATimeStamp = now

		log.Logger.Infof("证书登录携带的密钥对的时间戳:%s", utils.DateFormat(pkg.CATimeStamp))
		b := loginReqInstructor(pkg.CATimeStamp)
		SSendMsg(b)
		return nil
	} else {
		log.Logger.Trace("数据库有用户公钥,使用最新密钥对进行登录...")
		pkg.LoginPk = cert.PublicKey
		pkg.LoginSk = cert.PrivateKey
		pkg.CATimeStamp = cert.TimeStamp

		b := loginReqInstructor(pkg.CATimeStamp)
		SSendMsg(b)

		return nil
	}
}
func LoginSend() {
	//todo 用户登录

	RecoverFunc()
	time.Sleep(time.Second * 3)
	err := login()
	if err != nil {
		log.Logger.Errorf("证书登录失败,请联系平台")
		return
	}
}
