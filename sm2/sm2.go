package sm2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ZZMarquis/gm/sm2"
)

// keyTitle SM2标准公钥头
const keyTitle = "3059301306072a8648ce3d020106082a811ccf5501822d03420004"

var userId = []byte("1234567812345678")

// SetUserId 设置 userId
func SetUserId(u []byte) {
	userId = u
}

// rawBytesToPublicKey 解析公钥，获取 X, Y
func rawBytesToPublicKey(bytes []byte) (*sm2.PublicKey, error) {
	if len(bytes) <= 0 {
		return nil, errors.New("Public key error.")
	}

	asn1 := hex.EncodeToString(bytes)
	if !strings.Contains(asn1, keyTitle) {
		return nil, errors.New("Public key head error.")
	}

	xy := asn1[len(keyTitle):]
	x := xy[0 : len(xy)/2]
	y := xy[len(xy)/2:]

	publicKey := new(sm2.PublicKey)
	publicKey.Curve = sm2.GetSm2P256V1()
	publicKey.X, _ = new(big.Int).SetString(x, 16)
	publicKey.Y, _ = new(big.Int).SetString(y, 16)

	return publicKey, nil
}

// signAsn12Raw 将ASN1格式签名值转化为BC SM2 RAW 签名值
func signAsn12Raw(signature []byte) ([]byte, error) {
	resultBytes := make([]byte, 64)

	// 截取signR
	wPos := 3
	if (signature[wPos] & 0xFF) == 32 {
		wPos += 1
	} else if (signature[wPos] & 0xFF) == 33 {
		wPos += 2
	} else {
		return nil, errors.New("signR length Error!")
	}

	// 数组复制
	copy(resultBytes[0:32], signature[wPos:])
	wPos += 32
	// 截取signS
	wPos += 1
	if (signature[wPos] & 0xFF) == 32 {
		wPos += 1
	} else if (signature[wPos] & 0xFF) == 33 {
		wPos += 2
	} else {
		return nil, errors.New("signS length Error!")
	}

	copy(resultBytes[32:], signature[wPos:])

	return resultBytes, nil
}

// unmarshalSign 获取 r, s
func unmarshalSign(str string) (r, s *big.Int, err error) {
	d64, err := base64.StdEncoding.DecodeString(str)

	if err != nil {
		return nil, nil, errors.New("DecodeString sign error")
	}

	sign, err := signAsn12Raw(d64)
	if err != nil {
		return nil, nil, errors.New("signAsn12Raw error")
	}

	l := len(sign)
	br := sign[:l/2]
	bs := sign[l/2:]

	var ri, si big.Int
	r = ri.SetBytes(br)
	s = si.SetBytes(bs)

	return r, s, nil
}

// Sign 生成签名
func Sign(privateKey, src string) (string, error) {
	privateKeyByte, err := hex.DecodeString(privateKey)

	if err != nil {
		return "", err
	}

	pri, err := sm2.RawBytesToPrivateKey(privateKeyByte)
	if err != nil {
		return "", err
	}

	signature, err := sm2.Sign(pri, userId, []byte(src))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify 验证招商银行聚合支付 sm2 签名
func Verify(src, sign, publicKey string) (bool, error) {
	publicKeyByte, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return false, err
	}

	pub, err := rawBytesToPublicKey(publicKeyByte)
	if err != nil {
		return false, err
	}

	r, s, err := unmarshalSign(sign)
	if err != nil {
		return false, err
	}

	return sm2.VerifyByRS(pub, userId, []byte(src), r, s), nil
}

// GenerateKey 生成符合招行的密钥
func GenerateKey() (string, string, error) {
	pri, pub, err := sm2.GenerateKey(rand.Reader)

	if err != nil {
		return "", "", err
	}

	privateKey := hex.EncodeToString(pri.GetRawBytes())

	publicKey := keyTitle + hex.EncodeToString(pub.GetRawBytes())
	hexDecode, err := hex.DecodeString(publicKey)

	if err != nil {
		return "", "", err
	}

	publicKey = base64.StdEncoding.EncodeToString(hexDecode)

	return privateKey, publicKey, nil
}
