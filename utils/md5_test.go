package utils

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMD5(t *testing.T) {
	md5 := Md5([]byte("123456"))
	s := Md5([]byte("123456"))
	assert.Equal(t, md5, s)
}
func TestBytesToInt(t *testing.T) {
	var a uint32
	a = 123456
	bytes := IntToBytes(a)
	assert.Equal(t, 4, len(bytes))
	toInt := BytesToInt(bytes)
	fmt.Println(toInt)
}
func TestBytesToInt16(t *testing.T) {
	var a uint16
	a = 2222
	bytes := Int16ToBytes(a)
	assert.Equal(t, 2, len(bytes))
	toInt := BytesToInt16(bytes)
	fmt.Println(toInt)
}
