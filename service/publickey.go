package service

import (
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/utils"
	"encoding/json"
	"io"
	"net/http"
)

type TmpPublicKeyRequest struct {
	Username string `json:"Username"`
}
type TmpPublicKeyResponse struct {
	PublicKey string `json:"PublicKey"`
	TimeStamp string `json:"TimeStamp"`
}

func PublicKey(w http.ResponseWriter, r *http.Request) {
	var req TmpPublicKeyRequest
	var res TmpPublicKeyResponse
	all, err := io.ReadAll(r.Body)
	if err != nil {
		log.Logger.Errorf("read http msg from engine error:%s", err.Error())
		return
	}
	err = json.Unmarshal(all, &req)
	if err != nil {
		log.Logger.Errorf("json  unmarshal http  msg  error:%s", err.Error())
		return
	}
	if req.Username == "" {
		log.Logger.Errorf("username is empty")
		return
	}
	ca, err := model.FindLastCA(req.Username)
	if err != nil {
		log.Logger.Errorf("find last ca error:%s", err.Error())
		return
	}
	res.PublicKey = ca.PublicKey
	res.TimeStamp = utils.DateFormat(ca.TimeStamp)
	marshal, err := json.Marshal(res)
	if err != nil {
		log.Logger.Errorf("json marshal error:%s", err.Error())
		return
	}
	_, err = w.Write(marshal)
	if err != nil {
		log.Logger.Errorf("write http msg to engine error:%s", err.Error())
		return
	}
}
