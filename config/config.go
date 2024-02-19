package config

import (
	"DIMSCA/log"
	"DIMSCA/utils"
	"encoding/json"
	"os"
)

type Config struct {
	PlatformUrl string  `json:"PlatformUrl"`
	KeyPair     KeyPair `json:"KeyPair"`
	Local       Local   `json:"Local"`
}
type KeyPair struct {
	AutoConfig     bool   `json:"AutoConfig"`
	Algorithm      string `json:"Algorithm"`      //证书的生成算法rsa
	Bits           int    `json:"Bits"`           //证书生成的时候算法的位数有2096和1048
	PublicKeyPath  string `json:"PublicKeyPath"`  //私钥的存放路径
	PrivateKeyPath string `json:"PrivateKeyPath"` //公钥的存放路径
}

type Local struct {
	Host        string `json:"Host"`
	EthHost     string `json:"EthHost"`
	Port        int    `json:"Port"`
	User        string `json:"User"`
	Password    string `json:"Password"`
	CurrentDir  string `json:"CurrentDir"`
	IDentity    string `json:"IDentity"`
	LoggerLevel string `json:"LoggerLevel"` //日志级别
	NoConsole   bool   `json:"NoConsole"`
}

var ConfCa Config

func NewConfig(configPath string) (err error) {
	UpdateConfigCwd()
	var conf Config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(content, &conf); err != nil {
		return err
	}
	ConfCa = conf
	log.NoConsole = ConfCa.Local.NoConsole
	log.LoggerLevel = ConfCa.Local.LoggerLevel
	return nil
}
func UpdateIDentity(identity string) error {
	var c Config
	go func() {
		ConfigIDenUpdateCh <- []byte(identity)
	}()
	file, err := os.ReadFile(utils.GetConfigPosition(ConfCa.Local.CurrentDir))
	if err != nil {
		return err
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		return err
	}
	c.Local.IDentity = identity
	marshal, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile(utils.GetConfigPosition(ConfCa.Local.CurrentDir), marshal, 0666)
	if err != nil {
		return err
	}
	return nil
}
