package handle

import (
	"DIMSCA/log"
	"DIMSCA/pack"
	"github.com/gorilla/websocket"
)

var MsgBusCh chan []byte

func SSendMsg(msg []byte) {
	MsgBusCh <- msg
}
func Bus() {
	defer RecoverFunc()
	for {
		msg := <-MsgBusCh
		log.Logger.Debugf("消息总线发送消息:%s", string(msg))
		packet, err := pack.Packet(msg)
		if err != nil {
			log.Logger.Errorf("消息封包错误:%s", err.Error())
			return
		}
		err = CoreServerConn.WriteMessage(websocket.TextMessage, packet)
		if err != nil {
			log.Logger.Errorf("消息总线发送错误:%s", err.Error())
			return
		}
	}
}
