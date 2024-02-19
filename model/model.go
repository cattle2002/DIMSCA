package model

import (
	"DIMSCA/config"
	"DIMSCA/log"
	"DIMSCA/utils"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Model struct {
	gorm.Model
	User       string `gorm:"column:user;not null"`
	TimeStamp  int64  `gorm:"column:timeStamp;not null"`
	PublicKey  string `gorm:"column:publicKey;not null"`
	PrivateKey string `gorm:"column:privateKey"`
}

func (t *Model) TableName() string {
	return "cert"
}

var DB *gorm.DB
var err error

func NewCertFile() {
	DB, err = gorm.Open(sqlite.Open(utils.GetCertDBFilePosition(config.ConfCa.Local.CurrentDir)), &gorm.Config{})
	if err != nil {
		log.Logger.Fatalf("打开证书库失败")
	}
	err = DB.AutoMigrate(&Model{})
	if err != nil {
		log.Logger.Fatalf("打开证书库失败")
	}
}
