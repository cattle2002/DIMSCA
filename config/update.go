package config

var ConfigIDenUpdateCh chan []byte

// Update 将配置文件更新之后,没有的变量传进来,身份更新
func Update() {
	for {
		v := <-ConfigIDenUpdateCh
		ConfCa.Local.IDentity = string(v)
	}

}
