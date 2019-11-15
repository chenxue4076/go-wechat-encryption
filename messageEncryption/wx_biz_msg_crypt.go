package messageEncryption

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"sort"
)

/**
 * 用SHA1算法生成安全签名
 * @param string $token 票据
 * @param string $timestamp 时间戳
 * @param string $nonce 随机字符串
 * @param string $encrypt 密文消息
 */
func GetSHA1(token, timestamp, nonce, encryptMsg string) (msg string) {
	paramsArray := []string{token, timestamp, nonce, encryptMsg}
	sort.Strings(paramsArray)
	paramsMsg := ""
	for _,value := range paramsArray {
		//fmt.Println(value)
		paramsMsg += value
	}
	//sha1
	sha1Param := sha1.New()
	sha1Param.Write([]byte(paramsMsg))
	msg = hex.EncodeToString(sha1Param.Sum([]byte("")))
	return msg
}

type MsgFormat struct {
	ToUserName	string		`xml:"ToUserName"`
	Encrypt		string		`xml:"Encrypt"`
}

type MsgEncryptFormat struct {
	Encrypt			string		`xml:"Encrypt"`
	MsgSignature	string		`xml:"MsgSignature"`
	TimeStamp		string		`xml:"TimeStamp"`
	Nonce			string		`xml:"Nonce"`
}

/**
 * 提取出xml数据包中的加密消息
 * @param string $xmltext 待提取的xml字符串
 * @return string 提取出的加密消息字符串
 */
func XmlParseExtract(xmlText string) (errCode int, encrypt string, toUserName string) {
	msgFormat := MsgFormat{}
	err := xml.Unmarshal([]byte(xmlText), &msgFormat)
	if err != nil {
		errCode = WXBizMsgCryptParseXmlError
		return
	}
	errCode = WXBizMsgCryptOK
	encrypt = msgFormat.Encrypt
	toUserName = msgFormat.ToUserName
	return
}

/**
 * 生成xml消息
 * @param string $encrypt 加密后的消息密文
 * @param string $signature 安全签名
 * @param string $timestamp 时间戳
 * @param string $nonce 随机字符串
 */
func XmlParseGenerate(encrypt, signature, timestamp, nonce string) string  {
	AesTextResponseTemplate := `<xml>
<Encrypt><![CDATA[%s]]></Encrypt>
<MsgSignature><![CDATA[%s]]></MsgSignature>
<TimeStamp>%s</TimeStamp>
<Nonce><![CDATA[%s]]></Nonce>
</xml>`
	return fmt.Sprintf(AesTextResponseTemplate, encrypt, signature, timestamp, nonce)
}

/**
 * 构造函数
 * @param $token string 公众平台上，开发者设置的token
 * @param $encodingAesKey string 公众平台上，开发者设置的EncodingAESKey
 * @param $appId string 公众平台的appId
 */
type WXBizMsgCrypt struct {
	token string
	encodingAesKey string
	appId string
}

func Default(token, encodingAesKey, appId string) *WXBizMsgCrypt {
	wxBizMsgCrypt := &WXBizMsgCrypt{token,encodingAesKey,appId}
	return wxBizMsgCrypt
}

/**
 * 将公众平台回复用户的消息加密打包.
 * <ol>
 *    <li>对要发送的消息进行AES-CBC加密</li>
 *    <li>生成安全签名</li>
 *    <li>将消息密文和安全签名打包成xml格式</li>
 * </ol>
 *
 * @param $replyMsg string 公众平台待回复用户的消息，xml格式的字符串
 * @param $timeStamp string 时间戳，可以自己生成，也可以用URL参数的timestamp
 * @param $nonce string 随机串，可以自己生成，也可以用URL参数的nonce
 * @param &$encryptMsg string 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
 *                      当return返回0时有效
 *
 * @return int 成功0，失败返回对应的错误码
 */
func (wx *WXBizMsgCrypt)EncryptMsg(replyMsg, timeStamp, nonce string ) (encryptMsg string, errorCode int) {
	pc := PrpcryptDefault(wx.encodingAesKey)
	encryptBytes, errorCode := pc.Encrypt(replyMsg, wx.appId)
	if errorCode != WXBizMsgCryptOK {
		return
	}
	encryptBase64 := base64.StdEncoding.EncodeToString(encryptBytes)
	signature := GetSHA1(wx.token, timeStamp, nonce, encryptBase64)
	encryptMsg = XmlParseGenerate(encryptBase64, signature, timeStamp, nonce)
	return
}

/**
 * 检验消息的真实性，并且获取解密后的明文.
 * <ol>
 *    <li>利用收到的密文生成安全签名，进行签名验证</li>
 *    <li>若验证通过，则提取xml中的加密消息</li>
 *    <li>对消息进行解密</li>
 * </ol>
 *
 * @param $msgSignature string 签名串，对应URL参数的msg_signature
 * @param $timestamp string 时间戳 对应URL参数的timestamp
 * @param $nonce string 随机串，对应URL参数的nonce
 * @param $postData string 密文，对应POST请求的数据
 * @param &$msg string 解密后的原文，当return返回0时有效
 *
 * @return int 成功0，失败返回对应的错误码
 */
func (wx *WXBizMsgCrypt) DecryptMsg(msgSignature, timeStamp, nonce, postData string) (msg []byte, errorCode int) {
	if len(wx.encodingAesKey) != 43 {
		errorCode = WXBizMsgCryptIllegalAesKey
		return
	}
	errorCode, encrypt, toUserName := XmlParseExtract(postData)
	if errorCode != WXBizMsgCryptOK {
		return
	}
	//fmt.Println("Extract Info ", errorCode, encrypt, toUserName)
	signature := GetSHA1(wx.token, timeStamp, nonce, encrypt)
	//fmt.Println("new sign ", signature, "old sign ", msgSignature)
	if signature != msgSignature {
		errorCode = WXBizMsgCryptValidateSignatureError
		return
	}
	pc := PrpcryptDefault(wx.encodingAesKey)
	encryptBytes, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		fmt.Println("Base64 Decode error ",err.Error())
		errorCode = WXBizMsgCryptDecodeBase64Error
	}
	msg, errorCode = pc.Decrypt(encryptBytes, wx.appId)
	fmt.Println(toUserName)
	return
}