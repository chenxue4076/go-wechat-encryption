package msg_encrypt

import (
	"bytes"
	"encoding/binary"
)

//整形转换成字节
/*func IntToBytes(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, m)
	gbyte := bytesBuffer.Bytes()
	return gbyte
}*/

//整形转换成字节4位
func IntToBytes4(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, m)
	gbyte := bytesBuffer.Bytes()
	//c++ 高低位转换
	k := 4
	x := len(gbyte)
	nb := make([]byte, k)
	for i := 0; i < k; i++ {
		nb[i] = gbyte[x-i-1]
	}
	return nb
}

//整形转换成字节2位
/*func IntToBytes2(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, m)
	gbyte := bytesBuffer.Bytes()
	//c++ 高低位转换
	k := 2
	x := len(gbyte)
	nb := make([]byte, k)
	for i := 0; i < k; i++ {
		nb[i] = gbyte[x-i-1]
	}
	return nb
}*/

//字节转换成整形
/*func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}*/

//4个字节转换成整形
func Bytes4ToInt(b []byte) int {
	xx := make([]byte, 4)
	if len(b) == 2 {
		xx = []byte{b[0], b[1], 0, 0}
	} else {
		xx = b
	}
	m := len(xx)
	nb := make([]byte, 4)
	for i := 0; i < 4; i++ {
		nb[i] = xx[m-i-1]
	}
	bytesBuffer := bytes.NewBuffer(nb)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}