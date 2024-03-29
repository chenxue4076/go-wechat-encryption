package go_wechat_encryption

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

//用户向微信发送的事件
type MsgDecryptFormatEvent struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Content			string		`xml:"Content"`		//文本消息
	MsgId			string		`xml:"MsgId"`		//文本消息
	Event			string		`xml:"Event"`		//非文本时含有
	EventKey		string		`xml:"EventKey"`	//扫二维码带此参数
	Ticket			string		`xml:"Ticket"`		//扫二维码带此参数
	Latitude		float64		`xml:"Latitude"`	//地理位置
	Longitude		float64		`xml:"Longitude"`	//地理位置
	Precision		float64		`xml:"Precision"`	//地理位置
}
//本地服务器返回给微信服务器的消息格式
type MsgReplyFormatText struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Content			string		`xml:"Content"`
}

type MsgReplyFormatImage struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Image			[]MsgFormatImage	`xml:"Image"`
}
type MsgFormatImage struct {
	MediaId			string		`xml:"MediaId"`
}

type MsgReplyFormatVoice struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Voice			[]MsgFormatVoice	`xml:"Voice"`
}
type MsgFormatVoice struct {
	MediaId			string		`xml:"MediaId"`
}

type MsgReplyFormatVideo struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Video			[]MsgFormatVideo	`xml:"Video"`
}
type MsgFormatVideo struct {
	MediaId			string		`xml:"MediaId"`
	Title			string		`xml:"Title"`
	Description		string		`xml:"Description"`
}

type MsgReplyFormatMusic struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	Music			[]MsgFormatMusic	`xml:"Music"`
}
type MsgFormatMusic struct {
	Title			string		`xml:"Title"`
	Description		string		`xml:"Description"`
	MusicUrl		string		`xml:"MusicUrl"`
	HQMusicUrl		string		`xml:"HQMusicUrl"`
	ThumbMediaId	string		`xml:"ThumbMediaId"`
}

type MsgReplyFormatArticles struct {
	ToUserName		string		`xml:"ToUserName"`
	FromUserName	string		`xml:"FromUserName"`
	CreateTime		string		`xml:"CreateTime"`
	MsgType			string		`xml:"MsgType"`
	ArticleCount	string		`xml:"ArticleCount"`
	Articles		[]MsgFormatArticlesList	`xml:"Articles"`
}
type MsgFormatArticlesList struct {
	item			[]MsgFormatArticlesItem		`xml:"item"`
}
type MsgFormatArticlesItem struct {
	Title			string		`xml:"Title"`
	Description		string		`xml:"Description"`
	PicUrl			string		`xml:"PicUrl"`
	Url				string		`xml:"Url"`
}

/**
 * 提取出xml数据包中的加密消息
 * @param string $xmltext 待提取的xml字符串
 * @return string 提取出的加密消息字符串
 */
func XmlParseExtract(xmlText []byte) (errCode int, encrypt string, toUserName string) {
	msgFormat := MsgFormat{}
	err := xml.Unmarshal(xmlText, &msgFormat)
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
func XmlParseGenerate(encrypt, signature, timestamp, nonce string) []byte  {
	AesTextResponseTemplate := `<xml>
<Encrypt><![CDATA[%s]]></Encrypt>
<MsgSignature><![CDATA[%s]]></MsgSignature>
<TimeStamp>%s</TimeStamp>
<Nonce><![CDATA[%s]]></Nonce>
</xml>`
	return []byte(fmt.Sprintf(AesTextResponseTemplate, encrypt, signature, timestamp, nonce))
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
func (wx *WXBizMsgCrypt)EncryptMsg(replyMsg, timeStamp, nonce string ) (encryptMsg []byte, errorCode int) {
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
func (wx *WXBizMsgCrypt) DecryptMsg(msgSignature, timeStamp, nonce string, postData []byte) (msg []byte, errorCode int) {
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
	fmt.Println("To User ",toUserName)
	return
}