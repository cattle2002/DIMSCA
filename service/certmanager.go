package service

import (
	"DIMSCA/handle"
	"DIMSCA/log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// 允许所有的跨域请求，实际应用中需要根据需求配置
		return true
	},
} // use default options

func CertManager(w http.ResponseWriter, r *http.Request) {
	handle.ManagerConn, handle.Err = upgrader.Upgrade(w, r, nil)
	if handle.Err != nil {
		log.Logger.Errorf("upgrade ws error:%s", handle.Err.Error())
		return
	}
	handle.WsCAManager <- true
}
