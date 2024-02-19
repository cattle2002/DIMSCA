package config

import (
	"DIMSCA/pkg"
	"DIMSCA/utils"
	"encoding/json"
	"os"
)

func cwd() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return dir
}
func UpdateConfigCwd() {
	pwd := cwd()
	var c Config

	file, err := os.ReadFile(pkg.ConfigFileName)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		panic(err)
	}
	c.Local.CurrentDir = pwd
	marshal, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(pkg.ConfigFileName, marshal, 0666)
	if err != nil {
		panic(err)
	}
}
func GetPublicKeyPem() (string, error) {
	pem, err := utils.GetPublicKeyPem(ConfCa.Local.CurrentDir, ConfCa.KeyPair.PublicKeyPath)
	if err != nil {
		return "", nil
	}
	return pem, nil
}
func GetPrivateKeyPem() (string, error) {
	pem, err := utils.GetPrivateKeyPem(ConfCa.Local.CurrentDir, ConfCa.KeyPair.PrivateKeyPath)
	if err != nil {
		return "", nil
	}
	return pem, nil
}
