package protocol

type LoginReqPayload struct {
	ID             int64  `json:"ID"`
	Username       string `json:"Username"`
	Password       string `json:"Password"`
	PublicKey      string `json:"PublicKey"`
	PublicAlgoType string `json:"PublicKeyAlgoType"`
	TimeStamp      int64  `json:"TimeStamp"`
}
type LoginReq struct {
	Cmd     string          `json:"Cmd"`
	Program string          `json:"Program"`
	Payload LoginReqPayload `json:"Payload"`
}

type LoginResPayload struct {
	ID       int64  `json:"ID"`
	IDentity string `json:"IDentity"`
}
type LoginRes struct {
	Cmd     string          `json:"Cmd"`
	Program string          `json:"Program"`
	RetCode int             `json:"RetCode"`
	ErrMsg  string          `json:"ErrMsg"`
	Payload LoginResPayload `json:"Payload"`
}

// 证书同步协议
type CertGetFromSlaveReqPayload struct {
	ID             int64  `json:"ID"`
	PublicKey      string `json:"PublicKey"`
	Username       string `json:"Username"`
	PublicAlgoType string `json:"PublicKeyAlgoType"`
}
type CertGetFromSlaveReq struct {
	Cmd     string                     `json:"Cmd"`
	Program string                     `json:"Program"`
	Payload CertGetFromSlaveReqPayload `json:"Payload"`
}
type CertFromSlaveResPayload struct {
	ID int64 `json:"ID"`
	//CipherPrivateKey string `json:"CipherPrivateKey"`
	PublicKey        string `json:"PublicKey"`
	PublicKeyAgoType string `json:"PublicKeyAlgoType"`
}
type CertGetFromSlaveRes struct {
	Cmd     string `json:"Cmd"`
	Program string `json:"Program"`
	//RetCode int                     `json:"RetCode"`
	//ErrMsg  string                  `json:"ErrMsg"`
	Payload CertFromSlaveResPayload `json:"Payload"`
}
type CertGetFromSlaveRetPayload struct {
	ID               int64  `json:"ID"`
	CipherPrivateKey string `json:"CipherPrivateKey"`
	PublicKey        string `json:"PublicKey"`
}
type CertGetFromSlaveRet struct {
	Cmd     string                     `json:"Cmd"`
	Program string                     `json:"Program"`
	RetCode int                        `json:"RetCode"`
	Payload CertGetFromSlaveRetPayload `json:"Payload"`
}
type CertGetToMasterRetsPayload struct {
	ID               int64  `json:"ID"`
	CipherPrivateKey string `json:"CipherPrivateKey"`
	Username         string `json:"Username"`
	PublicKey        string `json:"PublicKey"`
}
type CertGetToMasterRets struct {
	Cmd     string                     `json:"Cmd"`
	Program string                     `json:"Program"`
	Payload CertGetToMasterRetsPayload `json:"Payload"`
}

type KeepReqPayload struct {
	ID        int64  `json:"ID"`
	User      string `json:"User"`
	LoginCode int    `json:"LoginCode"`
}
type KeepReq struct {
	Cmd     string         `json:"Cmd"`
	Program string         `json:"Program"`
	Payload KeepReqPayload `json:"Payload"`
}
type KeepRetPayload struct {
	ID        int64 `json:"ID"`
	TimeStamp int64 `json:"TimeStamp"`
}
type KeepRet struct {
	Cmd      string         `json:"Cmd"`
	Program  string         `json:"Program"`
	RetCode  int            `json:"RetCode"`
	ErrorMsg string         `json:"ErrorMsg"`
	Payload  KeepRetPayload `json:"Payload"`
}

type LoginCoreServerReqPayload struct {
	//ID       int64  `json:"ID"`
	//Time     int64  `json:"Time"`
	User              string `json:"Username"`
	Password          string `json:"Password"`
	PublicKey         string `json:"PublicKey"`
	PublicKeyAlgoType string `json:"PublicKeyAlgoType"`
}

type LoginCoreServerReq struct {
	Cmd     string                    `json:"Cmd"`
	Program string                    `json:"Program"`
	Payload LoginCoreServerReqPayload `json:"Payload"`
}
type LoginCoreServerResPayload struct {
	ID        int64  `json:"ID"`
	TimeStamp int64  `json:"TimeStamp"`
	Method    string `json:"Method"`
}
type LoginCoreServerRes struct {
	Cmd      string                    `json:"Cmd"`
	Program  string                    `json:"Program"`
	RetCode  int                       `json:"RetCode"`
	ErrorMsg string                    `json:"ErrorMsg"`
	Payload  LoginCoreServerResPayload `json:"Payload"`
}
type PKSKReq struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}
type PKSKRes struct {
	Code int    `json:"Code"`
	Msg  string `json:"Msg"`
	Pk   string `json:"Pk"`
	Sk   string `json:"Sk"`
}
type SingleSyncReqPayload struct {
	ID   int64  `json:"ID"`
	User string `json:"Seller"`
}
type SingleSyncReq struct {
	Cmd     string               `json:"Cmd"`
	Program string               `json:"Program"`
	Payload SingleSyncReqPayload `json:"Payload"`
}
type SingleSyncResPayload struct {
	ID        int64  `json:"ID"`
	AlgoType  string `json:"AlgoType"`
	PublicKey string `json:"PublicKey"`
}
type SingleSyncRes struct {
	Cmd      string               `json:"Cmd"`
	Program  string               `json:"Program"`
	RetCode  int                  `json:"RetCode"`
	ErrorMsg string               `json:"ErrorMsg"`
	Payload  SingleSyncResPayload `json:"Payload"`
}

type Cert2fReq struct {
	User       string `json:"User"`
	TimeStamp  int64  `json:"TimeStamp"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
}
type Cert2fRes struct {
	Code int    `json:"Code"`
	Msg  string `json:"Msg"`
	Data string `json:"Data"`
}

type CertListResPayload struct {
	User      string `json:"User"`
	PublicKey string `json:"PublicKey"`
}
type CertListRes struct {
	Code int                   `json:"Code"`
	Msg  string                `json:"Msg"`
	Data *[]CertListResPayload `json:"Data"`
}
type CertRemakeReq struct {
	Cmd string `json:"Cmd"`
}
type CertRemakeRes struct {
	Code int    `json:"Code"`
	Msg  string `json:"Msg"`
	Data string `json:"Data"`
}
