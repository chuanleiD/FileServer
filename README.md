# 一款简易的局域网文件服务器

作用：通过web浏览器向局域网中的其他用户分享文件。接收其他用户上传的文件。

分享文件夹：FileServer\content

上传文件保存位置：FileServer\upload

登录密钥：main.go 中

```go
var users = map[string]string{
	"admin": "admin",
	"user1": "userpass",
}
```

编译方法：`go build FileServer`

运行中展示：

![PixPin_2024-08-16_18-30-17](pic/PixPin_2024-08-16_18-30-17.png)

![PixPin_2024-08-16_18-31-05](pic/PixPin_2024-08-16_18-31-05.png)