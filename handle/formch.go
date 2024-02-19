package handle

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/pkg"
	"DIMSCA/protocol"
	"DIMSCA/utils"
	"encoding/json"
	"github.com/wenzhenxi/gorsa"
	"time"
)

func HandleLoginMsgCh() {
	v := <-LoginMsgCh
	var res protocol.LoginRes
	err := json.Unmarshal(v, &res)
	if err != nil {
		log.Logger.Errorf("json unmarshal error:%s", err.Error())
		return
	}
	if res.RetCode == 400 {
		log.Logger.Info("当前身份为从机")
		go func() {
			if res.Payload.IDentity == pkg.Slave {
				certGetFromSlaveReqInstructor()
				req, err2 := certGetToMasterRet()
				if err != nil {
					log.Logger.Errorf("解析消息错误:%s", err2.Error())
					return
				}
				//todo 使用公私钥进行解密
				decrypt, err := gorsa.PriKeyDecrypt(req.Payload.CipherPrivateKey, pkg.LoginSk)
				if err != nil {
					log.Logger.Errorf("Gorsa 私钥解密失败:%s", err.Error())
					return
				}
				pkg.DBSK = decrypt
				pkg.DBPK = req.Payload.PublicKey
				pkg.DBTimeStamp = time.Now().UnixMilli()
				err = utils.WritePem(pkg.DBPK, pkg.DBSK,
					utils.GetPublicKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PublicKeyPath),
					utils.GetPrivateKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PrivateKeyPath))
				if err != nil {
					log.Logger.Errorf("写入公私钥到文件失败:%s", err.Error())
					return
				}
				log.Logger.Info("密钥对写入文件成功")
				err = model.CreateWrapper(config.ConfCa.Local.User, pkg.DBTimeStamp, pkg.DBPK, pkg.DBSK)
				if err != nil {
					log.Logger.Errorf("同步公私钥到数据库失败:%s", err.Error())
					return
				}
				log.Logger.Infof("私钥写入数据库成功,密钥对时间戳%d:时间戳转日期%s", pkg.DBTimeStamp, utils.DateFormat(pkg.DBTimeStamp))

				err = config.UpdateIDentity(pkg.Slave)
				if err != nil {
					log.Logger.Errorf("更新机器身份失败:%s", err.Error())
					return
				}
				log.Logger.Infof("更新机器身份成功:%s", pkg.Slave)
			}
		}()
	}
	if res.RetCode == 405 {
		log.Logger.Errorf("用户名或者密码错误:%s", res.ErrMsg)
		return
	}
	if res.RetCode == 0 {
		log.Logger.Infof("返回信息主:%v", res)
		if res.Payload.IDentity == "Master" {
			//todo 将内存里面的公钥写到文件,然后更新机器身份
			err := utils.WritePem(pkg.LoginPk, pkg.LoginSk,
				utils.GetPublicKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PublicKeyPath),
				utils.GetPrivateKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PrivateKeyPath))
			if err != nil {
				log.Logger.Errorf("写入公私钥到文件失败:%s", err.Error())
				return
			}

			log.Logger.Info("密钥对写入文件成功")
			err = config.UpdateIDentity(pkg.Master)
			if err != nil {
				log.Logger.Errorf("更新机器身份失败:%s", err.Error())
				return
			}
			err = model.CreateWrapper(config.ConfCa.Local.User, pkg.CATimeStamp, pkg.LoginPk, pkg.LoginSk)
			if err != nil {
				log.Logger.Errorf("同步公私钥到数据库失败:%s", err.Error())
				return
			}
			log.Logger.Infof("私钥写入数据库成功,密钥对时间戳%d:时间戳转日期%s", pkg.CATimeStamp, utils.DateFormat(pkg.CATimeStamp))
			log.Logger.Infof("更新机器身份成功:%s", pkg.Master)
		} else {
			return
		}
	}
	if res.RetCode == protocol.FAFAFA {
		log.Logger.Infof("返回信息FAFAFA:%v", res)
		err := utils.WritePem(pkg.LoginPk, pkg.LoginSk, utils.GetPublicKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PublicKeyPath),
			utils.GetPrivateKeyPemPosition(config.ConfCa.Local.CurrentDir, config.ConfCa.KeyPair.PrivateKeyPath))
		if err != nil {
			log.Logger.Errorf("写入公私钥到文件失败:%s", err.Error())
			return
		}
		log.Logger.Infof("私钥写入文件成功,无需入库:密钥对时间戳:%d:时间戳转日期:%s", pkg.CATimeStamp, utils.DateFormat(pkg.CATimeStamp))
		err = config.UpdateIDentity(pkg.Slave)
		if err != nil {
			log.Logger.Errorf("更新机器身份失败:%s", err.Error())
			return
		}
		log.Logger.Info("更新机器身份成功")
	}
}
