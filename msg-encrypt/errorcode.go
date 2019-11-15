package msg_encrypt

/**
 * error code 说明.
 * <ul>
 *    <li>-40001: 签名验证错误</li>
 *    <li>-40002: xml解析失败</li>
 *    <li>-40003: sha加密生成签名失败</li>
 *    <li>-40004: encodingAesKey 非法</li>
 *    <li>-40005: appid 校验错误</li>
 *    <li>-40006: aes 加密失败</li>
 *    <li>-40007: aes 解密失败</li>
 *    <li>-40008: 解密后得到的buffer非法</li>
 *    <li>-40009: base64加密失败</li>
 *    <li>-40010: base64解密失败</li>
 *    <li>-40011: 生成xml失败</li>
 * </ul>
 */
const (
	WXBizMsgCryptOK						=	0
	WXBizMsgCryptValidateSignatureError	=	-40001
	WXBizMsgCryptParseXmlError			=	-40002
	WXBizMsgCryptComputeSignatureError	=	-40003
	WXBizMsgCryptIllegalAesKey			=	-40004
	WXBizMsgCryptValidateAppidError		=	-40005
	WXBizMsgCryptEncryptAESError		=	-40006
	WXBizMsgCryptDecryptAESError		=	-40007
	WXBizMsgCryptIllegalBuffer			=	-40008
	WXBizMsgCryptEncodeBase64Error		=	-40009
	WXBizMsgCryptDecodeBase64Error		=	-40010
	WXBizMsgCryptGenReturnXmlError		=	-40011
)

func WXBizMsgErrorMsg(errorCode int) string {
	switch errorCode {
	case WXBizMsgCryptOK:
			return "成功"
	case WXBizMsgCryptValidateSignatureError:
		return "-40001: 签名验证错误"
	case WXBizMsgCryptParseXmlError:
		return "-40002: xml解析失败"
	case WXBizMsgCryptComputeSignatureError:
		return "-40003: sha加密生成签名失败"
	case WXBizMsgCryptIllegalAesKey:
		return "-40004: encodingAesKey 非法"
	case WXBizMsgCryptValidateAppidError:
		return "-40005: appid 校验错误"
	case WXBizMsgCryptEncryptAESError:
		return "-40006: aes 加密失败"
	case WXBizMsgCryptDecryptAESError:
		return "-40007: aes 解密失败"
	case WXBizMsgCryptIllegalBuffer:
		return "-40008: 解密后得到的buffer非法"
	case WXBizMsgCryptEncodeBase64Error:
		return "-40009: base64加密失败"
	case WXBizMsgCryptDecodeBase64Error:
		return "-40010: base64解密失败"
	case WXBizMsgCryptGenReturnXmlError:
		return "-40011: 生成xml失败"
	default :
		return "未知错误"
	}
}