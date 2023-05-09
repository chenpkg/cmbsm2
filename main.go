package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/chenpkg/cmbsm2/sm2"
)

func resolveSrc(src string, src64 string) (string, error) {
	if src != "" {
		return src, nil
	}

	if src64 != "" {
		str, err := base64.StdEncoding.DecodeString(src64)
		if err != nil {
			return "", errors.New("decode src64 error")
		}

		return string(str), nil
	}

	return "", errors.New("error resolve src")
}

// runCommand 执行命令行程序
func runCommand() {
	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	src := signCmd.String("src", "", "content string")
	src64 := signCmd.String("src64", "", "content base64 string")
	pri := signCmd.String("pri", "", "private key")
	sUserId := signCmd.String("uid", "1234567812345678", "user id")

	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	vSrc := verifyCmd.String("src", "", "content string")
	vSrc64 := verifyCmd.String("src64", "", "content base64 string")
	pub := verifyCmd.String("pub", "", "public key")
	sign := verifyCmd.String("sign", "", "sign")
	vUserId := verifyCmd.String("uid", "1234567812345678", "user id")

	if len(os.Args) < 2 {
		fmt.Println("expected 'sign'、'verify'、'generate' commands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign":
		signCmd.Parse(os.Args[2:])
		sm2.SetUserId([]byte(*sUserId))

		content, err := resolveSrc(*src, *src64)
		if err != nil {
			os.Exit(1)
		}

		sign, err := sm2.Sign(*pri, content)
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(sign)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		sm2.SetUserId([]byte(*vUserId))

		content, err := resolveSrc(*vSrc, *vSrc64)
		if err != nil {
			os.Exit(1)
		}

		status, err := sm2.Verify(content, *sign, *pub)
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(status)
	case "generate":
		pri, pub, err := sm2.GenerateKey()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("private key")
		fmt.Println(pri)
		fmt.Println()
		fmt.Println("public key")
		fmt.Println(pub)
	default:
		fmt.Println("expected 'sign'、'verify'、'generate' commands")
		os.Exit(1)
	}
}

func main() {
	runCommand()
}
