package pkg

const (
	ConfigFileName = "configc.json"
	Master         = "Master"
	Slave          = "Slave"
	RSA            = "rsa"
	SM2            = "sm2"
	//DefaultCAAlgo  = "sm2"
	Sm2DefaultKey = "3132333435363738" //16进制   12345678

)

var CurrentCAAlgoType string
var (
	// 证书登录的时候，无论是从数据库拉取的密钥对,还是临时生成的密钥对 都先经过这里过滤一次,最后入库肯定是这里的密钥对
	//1.当程序里第一个没有证书
	//2.从数据库获取证书
	//3.证书程序登录返回从机
	//上面三次情况写入数据库的时候，都是这里的数据
	LoginPk     string
	LoginSk     string
	CATimeStamp int64
	DBPK        string
	DBSK        string
	DBTimeStamp int64
)
