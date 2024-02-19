//go:build darwin || freebsd || linux

package utils

func GetConfigPosition(cwd string) string {
	return cwd + "/" + "configc.json"
}

func GetPublicKeyPemPosition(cwd string, pkPos string) string {
	return cwd + "/" + pkPos
}
func GetPrivateKeyPemPosition(cwd string, skPos string) string {
	return cwd + "/" + skPos
}

func GetCertDBFilePosition(cwd string) string {
	return cwd + "/" + "cert.db"
}
func GetPrivateKeyPem(cwd string, skPos string) (string, error) {
	skPPos := GetPrivateKeyPemPosition(cwd, skPos)
	file, err := os.ReadFile(skPPos)
	if err != nil {
		return "", err
	}
	return string(file), nil
}

func GetPublicKeyPem(cwd string, pkPos string) (string, error) {
	pkPPos := GetPrivateKeyPemPosition(cwd, pkPos)
	file, err := os.ReadFile(pkPPos)
	if err != nil {
		return "", err
	}
	return string(file), nil
}

func PkBegin() string {
	return "-----BEGIN PUBLIC KEY-----\n"
}
func SkBegin() string {
	return "-----BEGIN Private key-----\n"
}
