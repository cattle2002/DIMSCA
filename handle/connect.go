package handle

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"context"
	"github.com/gorilla/websocket"
	"time"
)

func Connect() {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, config.ConfCa.PlatformUrl, nil)
	if err != nil {
		CoreServerConnStatusChRunning <- false
		CoreServerConnStatusChDaemon <- false
		log.Logger.Errorf("ca connect  coreServer error:%s", err.Error())
	} else {
		log.Logger.Info("connect coreServer  success")
		CoreServerConn = conn
		CoreServerConnStatusChRunning <- true
		CoreServerConnStatusChDaemon <- true
	}

}
