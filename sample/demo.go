package main

import (
	"encoding/xml"
	"fmt"
	"go-wechat-encryption"
)

func main()  {
	text := "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"
	timeStamp := "1409304348"
	nonce := "xxxxxx"
	wxBizMsgCrypt := go_wechat_encryption.Default("pamtest","abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG","wxb11529c136998cb6")
	encryptMsg, errorCode := wxBizMsgCrypt.EncryptMsg(text, timeStamp, nonce)
	if errorCode != 0 {
		fmt.Println("加密失败："+ go_wechat_encryption.WXBizMsgErrorMsg(errorCode))
	}
	fmt.Println("加密后："+encryptMsg)

	//解析xml
	msgEncryptFormat := go_wechat_encryption.MsgEncryptFormat{}
	err := xml.Unmarshal([]byte(encryptMsg), &msgEncryptFormat)
	if err != nil {
		fmt.Println("解析XML失败："+ err.Error())
	}
	fmt.Println("解析XML",msgEncryptFormat)

	msgFormat := `<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>`
	msgFormatXML := fmt.Sprintf(msgFormat, msgEncryptFormat.Encrypt)

	wxBizMsgDecrypt, errorCode := wxBizMsgCrypt.DecryptMsg(msgEncryptFormat.MsgSignature, timeStamp, nonce, msgFormatXML)
	if errorCode != 0 {
		fmt.Println("解密失败："+ go_wechat_encryption.WXBizMsgErrorMsg(errorCode))
	}
	fmt.Println("解密后：",string(wxBizMsgDecrypt))


}
