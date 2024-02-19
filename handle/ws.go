package handle

import (
	"DIMSCA/log"
	"encoding/json"
	"github.com/gorilla/websocket"
)

var ManagerConn *websocket.Conn
var Err error
var WsCAManager chan bool

func pkt(jsonStr []byte) (string, error) {
	mp := make(map[string]interface{})
	err := json.Unmarshal(jsonStr, &mp)
	if err != nil {
		log.Logger.Errorf("反序列化失败:%s", err.Error())
		return "", err
	}
	return mp["Cmd"].(string), nil
}

// 处理
func HandleWsManager() {
	<-WsCAManager
	for {
		log.Logger.Trace("reading manager msg...")
		_, p, err := ManagerConn.ReadMessage()
		if err != nil {
			log.Logger.Errorf("reading manager msg error:%s", err.Error())
			return
		}
		cmd, err := pkt(p)
		if err != nil {
			log.Logger.Errorf("pkt error:%s", err.Error())
			continue
		}
		if cmd == string(CertInput) {
			CertInputResponseSuccess()
		}
		if cmd == string(CertRemake) {
			CertRemakeResponseSuccess()
		}
		if cmd == string(CertSync) {
			CertSyncResponseSuccess()
		}
		if cmd == string(CertShow) {
			CertShowHandle()
		}
		if cmd == string(CertOwner) {
			CertOwnerHandle()
		}
	}
}
