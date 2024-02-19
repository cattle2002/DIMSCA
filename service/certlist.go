package service

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/model"
	"DIMSCA/protocol"
	"encoding/json"
	"net/http"
)

func convert(cs []model.Model) *[]protocol.CertListResPayload {
	var res []protocol.CertListResPayload
	for i := 0; i < len(cs); i++ {
		var ele protocol.CertListResPayload
		ele.User = cs[i].User
		ele.PublicKey = cs[i].PublicKey
		res = append(res, ele)
	}
	return &res
}
func serviceCertListError(errMsg string) []byte {
	var res protocol.CertListRes
	res.Code = protocol.ErrorCode
	res.Msg = errMsg
	marshal, _ := json.Marshal(res)
	return marshal
}
func serviceCertListSuccess(data *[]protocol.CertListResPayload) []byte {
	var res protocol.CertListRes
	res.Code = protocol.SuccessCode
	res.Data = data
	marshal, _ := json.Marshal(res)
	return marshal
}
func CertList(w http.ResponseWriter, r *http.Request) {
	user := model.CertListExcludeUser(config.ConfCa.Local.User)
	if user == nil {
		log.Logger.Info("当前未找到用户证书")
		listError := serviceCertListError("当前没有买家证书")
		_, err := w.Write(listError)
		if err != nil {
			log.Logger.Errorf("write msg error:%s", err.Error())
			return
		}
		return
	}
	xx := convert(*user)
	bs := serviceCertListSuccess(xx)
	_, err := w.Write(bs)
	if err != nil {
		log.Logger.Errorf("write msg error:%s", err.Error())
		return
	}
	return
}
