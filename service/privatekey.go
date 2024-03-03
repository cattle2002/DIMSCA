package service

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"encoding/json"
	"io"
	"net/http"
)

// var upgrader = websocket.Upgrader{} // use default options

//	func echo(w http.ResponseWriter, r *http.Request) {
//		c, err := upgrader.Upgrade(w, r, nil)
//		if err != nil {
//			log.Print("upgrade:", err)
//			return
//		}
type LocalRequest struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}
type LocalResponse struct {
	PrivateKey string `json:"PrivateKey"`
}

func PrivateKey(w http.ResponseWriter, r *http.Request) {
	var req LocalRequest
	var res LocalResponse
	all, err := io.ReadAll(r.Body)
	if err != nil {
		log.Logger.Errorf("read http msg from engine error:%s", err.Error())
		return
	}
	err = json.Unmarshal(all, &req)
	if err != nil {
		log.Logger.Errorf("json marshal error:%s", err.Error())
		res.PrivateKey = "Unmarshal Error"
		marshal, _ := json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return
	}
	log.Logger.Infof("api/v1/sk req:%v", req)
	if req.Username != config.ConfCa.Local.User {
		log.Logger.Infof("req name:%s  isnot config name:%s", req.Username, config.ConfCa.Local.User)
		res.PrivateKey = "User Not  Found"
		marshal, _ := json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return
	}
	if req.Password != config.ConfCa.Local.Password {
		log.Logger.Infof("req password:%s is not cofig password:%s", req.Password, config.ConfCa.Local.Password)
		res.PrivateKey = "Password Not  Found"
		marshal, _ := json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return

	}
	_, err = config.GetPublicKeyPem()
	if err != nil {
		log.Logger.Errorf("user privatekey not found:%s", err.Error())
		res.PrivateKey = "Public Key Not Found" + err.Error()
		marshal, _ := json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return
	}
	pem, err := config.GetPrivateKeyPem()
	if err != nil {
		log.Logger.Errorf("private key not found:%s", err.Error())
		res.PrivateKey = "Private Key Not Found"
		marshal, _ := json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return
	}
	res.PrivateKey = pem
	marshal, err := json.Marshal(res)
	if err != nil {
		log.Logger.Errorf("json marshal error:%s", err.Error())
		res.PrivateKey = "marshal Error"
		marshal, _ = json.Marshal(res)
		_, err = w.Write(marshal)
		if err != nil {
			log.Logger.Errorf("write http msg to engine error:%s", err.Error())
			return
		}
		return
	}
	_, err = w.Write(marshal)
	if err != nil {
		log.Logger.Errorf("write http msg to engine error:%s", err.Error())
		return
	}
	log.Logger.Info("api/v1/sk  success")

	return
}
