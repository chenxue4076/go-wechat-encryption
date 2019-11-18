package go_wechat_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"time"
)

type Prpcrypt struct {
	key		string
}

func PrpcryptDefault(key string) *Prpcrypt {
	prpcrypt := &Prpcrypt{key}
	return prpcrypt
}

func (p *Prpcrypt) Encrypt(text, appId string) (result []byte, errorCode int) {
	//fmt.Println("Encrypt before text",text)
	// 16位随机字符串添加到明文开头
	random := p.randomStr()
	//fmt.Println("Encrypt random",random)
	pack := IntToBytes4(len(text))
	//fmt.Println("Encrypt pack",pack)
	//text = random + string(pack) + text + appId
	textBytes := append([]byte(random), pack[:]...)
	textBytes = append(textBytes, []byte(text)...)
	textBytes = append(textBytes, []byte(appId)...)
	//fmt.Println("Encrypt after text",textBytes)
	//使用自定义的填充方式对明文进行补位填充
	textOrigin := PKCS7EncoderEncode(textBytes)
	//fmt.Println("Encrypt after PKCS7EncoderEncode",textOrigin)
	//加密
	block,err := aes.NewCipher([]byte(p.key[:PKCS7EncoderBlockSize]))
	//fmt.Println("Encrypt after block",block)
	if err != nil {
		fmt.Println("Encrypt err",err.Error())
		errorCode = WXBizMsgCryptEncryptAESError
		return
	}
	cipherText := make([]byte,aes.BlockSize+len(textOrigin))
	//block大小 16
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(cryptoRand.Reader,iv); err != nil {
		fmt.Println("Encrypt iv err",err.Error())
		errorCode = WXBizMsgCryptEncryptAESError
		return
	}
	//fmt.Println("CBC Encrypt")
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], textOrigin)
	//fmt.Println("Encrypt resultBytes",resultBytes)
	//result = base64.StdEncoding.EncodeToString(resultBytes)
	result = cipherText
	//fmt.Println("Encrypt result",result)
	return
}

func (p *Prpcrypt) Decrypt(encrypted []byte, appId string) (result []byte, errorCode int) {
	block,err := aes.NewCipher([]byte(p.key[:PKCS7EncoderBlockSize]))
	if err != nil {
		errorCode = WXBizMsgCryptEncryptAESError
		return
	}
	if len(encrypted) < aes.BlockSize {
		errorCode = WXBizMsgCryptDecodeBase64Error
		return
	}
	//block大小 16
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]
	if len(encrypted) % aes.BlockSize != 0 {
		errorCode = WXBizMsgCryptIllegalBuffer
		return
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encrypted, encrypted)
	encrypted = PKCS7EncoderDecode(encrypted)
	//去除16位随机字符串
	encrypted = encrypted[16:]
	xmlLen := Bytes4ToInt(encrypted[:4])
	xmlContent := encrypted[4:xmlLen+4]
	fromAppId := encrypted[xmlLen+4:]
	if string(fromAppId) != appId {
		errorCode = WXBizMsgCryptValidateAppidError
		return
	}
	result = xmlContent
	return
}

/**
 * 随机生成16位字符串
 * @return string 生成的字符串
 */
func (p *Prpcrypt) randomStr() string {
	strPol := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
	bytesPol := []byte(strPol)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 16; i++ {
		result = append(result, bytesPol[r.Intn(len(bytesPol))])
	}
	return string(result)
}

