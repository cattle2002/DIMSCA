package protocol

type CoreServerCmd string

const (
	Login              CoreServerCmd = "Login"
	LoginRet           CoreServerCmd = "LoginRet"
	Program            CoreServerCmd = "Cert"
	CertFromSlave      CoreServerCmd = "GetCertFromMaster"
	CertFromSlaveRet   CoreServerCmd = "GetCertForSlave"
	CertGetToMasterRet CoreServerCmd = "GetCertFromMasterRet"
	KeepRets           CoreServerCmd = "KeepRet"
	SuccessMsg         CoreServerCmd = "success"
	ErrorMsg           CoreServerCmd = "failed"
	CertRemake         CoreServerCmd = "CertRemake"
	GetCertForSlaveRet CoreServerCmd = "GetCertForSlaveRet"
)
const SuccessCode = 0
const FAFAFA = 888
const ErrorCode = -400
const FSuccessCode = 200
const FErrorCode = 400
const FSuccessMsg = "success"
