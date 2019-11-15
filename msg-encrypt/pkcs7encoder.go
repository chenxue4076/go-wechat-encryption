package msg_encrypt

import "bytes"

/**
 * 对需要加密的明文进行填充补位
 * @param $text 需要进行填充补位操作的明文
 * @return 补齐明文字符串
 */

var PKCS7EncoderBlockSize = 32

func PKCS7EncoderEncode(cipherText []byte) []byte {
	amountToPad := PKCS7EncoderBlockSize - (len(cipherText) % PKCS7EncoderBlockSize)
	padText := bytes.Repeat([]byte{byte(amountToPad)}, amountToPad)
	return append(cipherText, padText...)
}

/**
 * 对解密后的明文进行补位删除
 * @param decrypted 解密后的明文
 * @return 删除填充补位后的明文
 */
func PKCS7EncoderDecode(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	if unPadding < 1 || unPadding > 32 {
		unPadding = 0
	}
	return origData[:(length - unPadding)]
}