package handle

type ManagerCmd string

const (
	CertInput     ManagerCmd = "CertInput"
	CertInputRet  ManagerCmd = "CertInputRet"
	CertRemake    ManagerCmd = "CertRemake"
	CertRemakeRet ManagerCmd = "CertRemakeRet"
	CertSync      ManagerCmd = "CertSync"
	CertSyncRet   ManagerCmd = "CertSyncRet"
	CertShow      ManagerCmd = "CertShow"
	CertShowRet   ManagerCmd = "CertShowRet"
	CertOwner     ManagerCmd = "CertOwner"
	CertOwnerRet  ManagerCmd = "CertOwnerRet"
)
