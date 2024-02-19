package handle

import "DIMSCA/log"

func RecoverFunc() {
	// 使用recover捕获panic
	if r := recover(); r != nil {
		log.Logger.Errorf("catch panic:%v", r)
		return
	}
}
