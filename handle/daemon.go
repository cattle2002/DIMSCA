package handle

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/pack"
	"DIMSCA/protocol"
	"DIMSCA/utils"
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

func coroutinue() {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)
		<-sigChan
		defer CoreServerConn.Close()
		log.Logger.Info("ctrl +c  defer close coreServer")
		os.Exit(2)
	}()
}
func keepLive() {
	//keepLive
	go func() {
		for {
			time.Sleep(time.Second * 60 * 5)
			var kp protocol.KeepReq
			kp.Cmd = "Keep"
			kp.Program = "Cert"
			kp.Payload.ID = utils.MsgID()
			kp.Payload.User = config.ConfCa.Local.User
			kp.Payload.LoginCode = 200
			marshal, err := json.Marshal(kp)
			if err != nil {
				log.Logger.Errorf("json marshal error:%s", err.Error())
			}
			packet, err := pack.Packet(marshal)
			if err != nil {
				log.Logger.Errorf("packet error:%s", err.Error())
			}
			err = CoreServerConn.WriteMessage(websocket.TextMessage, packet)
			if err != nil {
				log.Logger.Errorf("write msg coreserver error:%s", err.Error())
			}
			log.Logger.Infof("write keeplive req:%v", kp)
		}
	}()
}
func reconnect() {
	go func() {
		for {
			v := <-CoreServerConnStatusChDaemon
			if !v {
				time.Sleep(time.Second * 3)
				ctx, _ := context.WithTimeout(context.Background(), time.Second*10)
				conn, _, err := websocket.DefaultDialer.DialContext(ctx, config.ConfCa.PlatformUrl, nil)
				if err != nil {
					CoreServerConnStatusChRunning <- false
					CoreServerConnStatusChDaemon <- false
					log.Logger.Errorf("reconnect coreServer error:%s", err.Error())
				} else {
					log.Logger.Info("reconnect coreServer success")
					CoreServerConn = conn
					CoreServerConnStatusChRunning <- true
					CoreServerConnStatusChDaemon <- true
				}
			}
		}
	}()
}
func Daemon() {
	defer func() {
		if err := recover(); err != nil {
			log.Logger.Error(err)
		}
	}()
	coroutinue()
	keepLive()
	reconnect()
}
