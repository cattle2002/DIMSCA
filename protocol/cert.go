package protocol

// 导入证书
type CertInputReq struct {
	Cmd        string `json:"Cmd"`
	User       string `json:"User"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
}
type CertInputRes struct {
	IpAddr string `json:"IpAddr"`
	Cmd    string `json:"Cmd"`
	Code   int    `json:"Code"`
	Msg    string `json:"Msg"`
}

// 重新生成证书
type CertRemakeReqX struct {
	Cmd string `json:"Cmd"`
}
type CertRemakeResX struct {
	IpAddr string `json:"IpAddr"`
	Cmd    string `json:"Cmd"`
	Code   int    `json:"Code"`
	Msg    string `json:"Msg"`
	Data   string `json:"Data"`
}

// 同步平台证书
type CertSyncReq struct {
	Cmd string `json:"Cmd"`
}
type CertSyncRes struct {
	IpAddr string `json:"IpAddr"`
	Cmd    string `json:"Cmd"`
	Code   int    `json:"Code"`
	Msg    string `json:"Msg"`
	Data   string `json:"Data"`
}

// 查看用户证书
type CertShowReq struct {
	Cmd string `json:"Cmd"`
}
type CertShowResPayload struct {
	User      string `json:"User"`
	PublicKey string `json:"PublicKey"`
}
type CertShowRes struct {
	IpAddr string               `json:"IpAddr"`
	Cmd    string               `json:"Cmd"`
	Code   int                  `json:"Code"`
	Msg    string               `json:"Msg"`
	Data   []CertShowResPayload `json:"Data"`
}
type CertOwnerReq struct {
	Cmd string `json:"Cmd"`
}
type CertOwnerRes struct {
	IpAddr     string `json:"IpAddr"`
	Cmd        string `json:"Cmd"`
	Code       int    `json:"Code"`
	Msg        string `json:"Msg"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
}
