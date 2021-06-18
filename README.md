# ACM SDK for Golang

```go
conf := nacos.NewAcm(func(c *NacosConfig) {
	c.EndPoint = "acm.aliyun.com"
    c.SpasAccessKey = "xxxxx"
    c.SpasSecretKey = "xxxxxxxxxx"
    c.PollTime = 20*time.Second // 设置监听轮询周期，默认10秒
})

// 异步监听配置
conf.ListenAsync("8b073ff4-1e58-41e9-ae72-37f8736bc9d4", "DEFAULT_GROUP", "test", func(cnf string) {
	// 重启程序
    os.Exit(1)
})

// 同步获取配置
conf.Get("8b073ff4-1e58-41e9-ae72-37f8736bc9d4", "DEFAULT_GROUP", "test")
```