<h1 align="center">招商银行聚合支付 sm2 国密签名、验签</h1>

<p align="center"> 招商银行聚合支付 sm2 签名、验签工具 </p>

## Usage

```shell
# 签名
$ ./bin/sm2 sign -pri "私钥..." -src "待签名字符串..."
MEUCIQC58u8spsvtRF/FEcDYJqtytPt8I2CgPwybk5810+A0KQIgcreDl9rKl0P26JKkw2qA6ALsiiYBQr1xlwhrbv+l284=
# 验签
$ ./bin/sm2 verify -pub "公钥..." -sign "待验签签名..." -src "待验签字符串"
true
# 生成密钥
$ ./bin/sm2 generate
private key
2cccea276de3eb8035ca9e8f1394a0dfd6d16ccfb44f7fd5ec2f705941b184e4

public key
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEeE/oyDVIBZoQiamV/l5fuHfKFuN2aftGBYd3g7gZM+g52xHZBekFljyrcaGw+ZwnUB1tsIGOLZ3KaaVM4tub9Q==
```

> 如果需要指定 user id，则加上 uid 参数即可。uid 默认使用 1234567812345678

> `src` 内容如果有引号之类的符号，可使用 `src64` 代替 `src` 传输 `base64` 字符串

> `./bin/sm2.exe` 与 `./bin/sm2` 基于 `windows/amd64` 与 `linux/amd64` 编译打包，如需其他系统版本程序可自行编译打包。

## License

MIT
