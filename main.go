package main

import "C"
import (
	"DIMSCA/config"
	"DIMSCA/handle"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/pkg"
	"DIMSCA/service"
	"DIMSCA/utils"
	"net/http"
	"strconv"
)

func IniChannel() {
	utils.Clear()
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
//func main() {
//}
//export CaRunning

func main() {
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
