### 证书动态库
因为sm2 不支持私钥加密(改成签名的形式) 受到影响的函数,以前的私钥加密替换成签名*
```
dataEnigne-go:
SymmetricKey 对称加密
GetUserPrivateKeyLocalCa 获取用户私钥
*AsymmetricEncryptDouble 确权授权
GrantPermission 授权
ConfirmPermission 确权
```