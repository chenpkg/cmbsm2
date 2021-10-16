package main

import (
	"testing"
)

func TestSign(t *testing.T) {
	privateKey := "D5F2AFA24E6BA9071B54A8C9AD735F9A1DE9C4657FA386C09B592694BC118B38"
	src := "biz_content={\"merId\":\"xxxxxxxx\",\"userId\":\"xxxxxxxx\",\"orderId\":\"202110160150337498\",\"notifyUrl\":\"https:\\/\\/baidu.com\",\"txnAmt\":10,\"tradeScene\":\"OFFLINE\"}&encoding=UTF-8&signMethod=02&version=0.0.1"

	_, err := Sign(privateKey, src)
	if err != nil {
		t.Errorf("sign error %s", err)
	}
}

func TestVerify(t *testing.T) {
	publicKey := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE6Q+fktsnY9OFP+LpSR5Udbxf5zHCFO0PmOKlFNTxDIGl8jsPbbB/9ET23NV+acSz4FEkzD74sW2iiNVHRLiKHg=="

	sign := "MEYCIQCEFKYniGb9HVUT+iv+Ml2Bmh9Clt+6M4TWHUeiXGpbugIhAH8/nVsactF8snc4kWQsJr+B989HRZnH/nTy0ZH+INRT"

	src := "encoding=UTF-8&errCode=SIGN_ERROR&respMsg=签名错误:RQZ7014&returnCode=FAIL&signMethod=02&version=0.0.1"

	status, err := Verify(src, sign, publicKey)
	if err != nil {
		t.Errorf("verify error %s", err)
	}

	if status != true {
		t.Error("verify fail")
	}
}
