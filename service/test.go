package service

import "net/http"

func Test(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello,world"))
}
