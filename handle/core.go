package handle

import (
	"DIMSCA/log"
	"DIMSCA/pack"
	"DIMSCA/protocol"
	"encoding/json"
	"github.com/gorilla/websocket"
)

var CoreServerConnStatusChDaemon chan bool
var CoreServerConnStatusChRunning chan bool

var CoreServerConn *websocket.Conn
var LoginMsgCh chan []byte
var CertGetFromSlaveRetCh chan []byte
var CertGetToMasterRetCh chan []byte
var CoreServerLoginRetCh chan []byte
var CertReMakeCh chan []byte

//var FirstCertTimeStamp int64

func MonitorHandle() {
	for {
		v := <-CoreServerConnStatusChRunning
		if v {
			for {
				log.Logger.Info("ca reading coreServer msg....")
				_, p, err := CoreServerConn.ReadMessage()
				if err != nil {
					log.Logger.Infof("ca reading coreServer msg error:%s", err.Error())
					CoreServerConnStatusChDaemon <- false
					break
				} else {
					packet, err := pack.UPacket(p)
					if err != nil {
						log.Logger.Errorf("upacket msg error:%s", err.Error())
						continue
					}
					log.Logger.Infof("ca recive  coreServer msg:%s", string(packet))
					value, _ := pack.ExtractCmdValue(string(packet))
					if err != nil {
						//todo
						log.Logger.Errorf("split coreServer msg error:%s", err.Error())
						continue
					}
					if value == string(protocol.LoginRet) { //处理核心服务器的登录应答请求
						LoginMsgCh <- packet
						HandleLoginMsgCh()
					}

					if value == string(protocol.CertFromSlaveRet) {
						//todo 这个消息的处理程序 必须需要确定的身份的程序
						log.Logger.Infof("read getcertforSlave ret:%s", value)
						CertGetFromSlaveRetCh <- packet
						err := CertGetFromSlaveRetHandle()
						if err != nil {
							log.Logger.Errorf("handle getcertforslave error:%s", err.Error())
							continue
						}
					}
					if value == string(protocol.KeepRets) {
						var res protocol.KeepRet
						err := json.Unmarshal(packet, &res)
						if err != nil {
							log.Logger.Error(err)
							continue
						}

					}
					if value == string(protocol.CertGetToMasterRet) {
						CertGetToMasterRetCh <- packet
					}
				}
			}
		} else {
			log.Logger.Error("正在连接核心服务器")
		}
	}
}
