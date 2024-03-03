package model

import (
	"DIMSCA/log"
	"errors"
	"gorm.io/gorm"
)

// 创建用户证书记录
func Create(user string, timestamp int64, pk string, sk string) error {
	var cert Model
	cert.User = user
	cert.PublicKey = pk
	cert.PrivateKey = sk
	cert.TimeStamp = timestamp
	tx := DB.Create(&cert)
	return tx.Error
}

// CreateWrapper 插入记录到数据库的时候，先记录是否存在这条数据才插入[用户公私钥专用]
func CreateWrapper(user string, timestamp int64, pk string, sk string) error {
	find, err := Find(user, timestamp, pk, sk)
	if err != nil {
		return err
	} else {
		if find {

			return nil
		} else {
			tx2 := Create(user, timestamp, pk, sk)
			return tx2
		}
	}
}
func Find(user string, timeStamp int64, pk string, sk string) (bool, error) {
	var cert Model
	tx := DB.Where("user = ? and  timeStamp = ? and publicKey = ? and privateKey = ?", user, timeStamp, pk, sk).Find(&cert)
	if tx.Error != nil {
		return false, err
	} else {
		if cert.ID == 0 {
			return false, nil
		} else {
			return true, nil
		}
	}
}
func FindLastCA(user string) (*Model, error) {
	var certs []Model
	var crt Model
	tx := DB.Where("user = ?", user).Order("timeStamp DESC").Find(&certs)

	if len(certs) == 0 {
		return &crt, nil
	}
	return &certs[0], tx.Error
}

// 查询用户最新的证书
//func OwnerLatestCertFix(user string) (*Model, error) {
//	var certs []Model
//	var crt Model
//	tx := DB.Where("user = ?", user).Order("timeStamp DESC").Find(&certs)
//	//通过timeStamp进行降序排列
//	if len(certs) == 0 {
//		crt.ID = 0
//		return &crt, nil
//	}
//	return &certs[0], tx.Error
//}

func OwnerLatestCert(user string) (*Model, error) {
	var users []Model
	var userx Model
	var Max int64
	tx := DB.Debug().Where("user = ?", user).Find(&users)
	log.Logger.Tracef("查看查询到的用户证书:%v", users)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		} else {
			return nil, tx.Error
		}
	} else {
		if len(users) == 0 {
			userx.ID = 0
			return &userx, errors.New("NO Cert")
		}
		log.Logger.Trace("Trace")
		for i := 0; i < len(users); i++ {
			if len(users) == 1 {
				userx = users[i]
				return &userx, nil
			} else {
				if users[i].TimeStamp > users[i+1].TimeStamp {
					Max = int64(i)
				} else {
					Max = int64(i + 1)
				}
			}
		}
	}
	userx = users[Max]
	log.Logger.Tracef("Max:%v", Max)
	return &userx, nil
}

//func UpdateUserPublicKey(user string, timeStamp int64, pk string) error {
//	CertDB.Where()
//}

func FindCertByUsername(user string) (*Model, error) {
	var ucerts []Model
	tx := DB.Where("user = ?", user).Order("timestamp DESC").Find(&ucerts)
	if len(ucerts) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &ucerts[0], tx.Error
}

// CertListExcludeUser 返回不包括user的其他user的信息
func CertListExcludeUser(user string) *[]Model {
	var certs []Model
	tx := DB.Debug().Where("user != ?", user).Find(&certs)
	if len(certs) != 0 {
		return &certs
	} else {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			log.Logger.Errorf("record not found:%s", tx.Error.Error())
			return nil
		}
		return nil
	}
}

// 查询当前用户的时间戳在数据库是否存在
// func CertFindTimeStamp(user string, timeStamp int64) error {

// }
