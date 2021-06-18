package acm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	contentType      = "application/x-www-form-urlencoded;charset=utf-8"
	splitConfig      = string(rune(1))
	splitConfigInner = string(rune(2))
)

type Acm struct {
	HttpClient        *http.Client
	EndPoint          string
	RamServer         string
	ServerAddr        string
	SpasAccessKey     string
	SpasSecretKey     string
	SpasSecurityToken string
	RoleName          string
	tokenTTL          time.Duration
	Logger            logger
	PollTime          time.Duration
}

type StsResponse struct {
	AccessKeyId     string    `json:"AccessKeyId"`
	AccessKeySecret string    `json:"AccessKeySecret"`
	SecurityToken   string    `json:"SecurityToken"`
	Expiration      time.Time `json:"Expiration"`
	LastUpdated     time.Time `json:"LastUpdated"`
	Code            string    `json:"Code"`
}

func NewAcm(options ...func(c *Acm)) *Acm {
	nc := &Acm{
		HttpClient: http.DefaultClient,
		EndPoint:   "acm.aliyun.com",
		RamServer:  "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
		Logger:     &defualtLogger{},
		PollTime:   10 * time.Second,
	}

	for _, option := range options {
		option(nc)
	}

	if err := nc.getServer(); err != nil {
		panic(err)
	}

	if nc.RoleName != "" {
		if err := nc.getRamToken(); err != nil {
			panic(err)
		}
	}

	return nc
}

func (n *Acm) getServer() error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:8080/diamond-server/diamond", n.EndPoint), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", contentType)

	resp, err := n.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bb, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("acm get server fail:%s", string(bb))
	}

	n.ServerAddr = strings.TrimSpace(string(bb))
	return nil
}

func (n *Acm) getRamToken() error {
	n.Logger.Debug(fmt.Sprintf("ram login server:[%s:%s]", n.ServerAddr, n.RoleName))

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s", n.RamServer, n.RoleName), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", contentType)

	resp, err := n.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bb, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("ram login fail:%s", string(bb))
	}

	ramResp := &StsResponse{}

	if err := json.Unmarshal(bb, ramResp); err != nil {
		return err
	}

	if ramResp.Code != "Success" {
		return fmt.Errorf("ram login fail:%s", string(bb))
	}

	n.SpasAccessKey = ramResp.AccessKeyId
	n.SpasSecretKey = ramResp.AccessKeySecret
	n.SpasSecurityToken = ramResp.SecurityToken
	n.tokenTTL = ramResp.Expiration.Sub(time.Now())

	return nil
}

func (n *Acm) Get(namespace, group, dataId string) (string, error) {
	n.Logger.Debug(fmt.Sprintf("acm get config:[namespace:%s,group:%s,dataId:%s]", namespace, group, dataId))

	v := url.Values{}
	v.Add("tenant", namespace)
	v.Add("group", group)
	v.Add("dataId", dataId)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/diamond-server/config.co?", n.ServerAddr)+v.Encode(), nil)
	if err != nil {
		return "", err
	}

	timeStamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)

	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Spas-AccessKey", n.SpasAccessKey)
	req.Header.Add("timeStamp", timeStamp)

	if n.SpasSecurityToken != "" {
		req.Header.Add("Spas-SecurityToken", n.SpasSecurityToken)
	}

	str := namespace + group + timeStamp
	sign := hmacSHA1(n.SpasAccessKey, str)

	req.Header.Add("Spas-Signature", sign)

	resp, err := n.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bb, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("nacos get fail:%s", string(bb))
	}

	return string(bb), nil
}

func (n *Acm) ListenAsync(namespace, group, dataId string, fn func(cnf string)) {
	ret, err := n.Get(namespace, group, dataId)
	if err != nil {
		panic(err)
	}

	contentMd5 := md5string(ret)

	go func() {
		t1 := time.NewTicker(n.tokenTTL)
		t2 := time.NewTicker(n.PollTime)
		for {
			select {
			// token到期刷新
			case <-t1.C:
				if err := n.getRamToken(); err != nil {
					n.Logger.Error(err)
				}
			// 每10秒监听配置
			case <-t2.C:
				update, err := n.Listen(namespace, group, dataId, contentMd5)
				if err != nil {
					n.Logger.Error(err)
					continue
				}
				if update {
					n.Logger.Debug(fmt.Sprintf("acm listen refresh:[namespace:%s,group:%s,dataId:%s]", namespace, group, dataId))
					ret, err := n.Get(namespace, group, dataId)
					if err != nil {
						n.Logger.Error(err)
						continue
					}

					contentMd5 = md5string(ret)
					fn(ret)
				}
			}
		}
	}()
}

func (n *Acm) Listen(namespace, group, dataId, md5 string) (bool, error) {
	n.Logger.Debug(fmt.Sprintf("acm listen start:[namespace:%s,group:%s,dataId:%s]", namespace, group, dataId))

	content := dataId + splitConfigInner + group + splitConfigInner + md5 + splitConfigInner + namespace + splitConfig

	v := url.Values{}
	v.Add("Probe-Modify-Request", content)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/diamond-server/config.co", n.ServerAddr), strings.NewReader(v.Encode()))
	if err != nil {
		return false, err
	}

	timeStamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)

	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Spas-AccessKey", n.SpasAccessKey)
	req.Header.Add("timeStamp", timeStamp)

	if n.SpasSecurityToken != "" {
		req.Header.Add("Spas-SecurityToken", n.SpasSecurityToken)
	}

	str := namespace + group + timeStamp
	sign := hmacSHA1(n.SpasAccessKey, str)

	req.Header.Add("Spas-Signature", sign)

	resp, err := n.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	bb, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("acm listen response error:%s", string(bb))
	}

	result := strings.Split(string(bb), "%02")

	// 如果返回数据不为空则代表有变化的文件
	if len(result) > 0 && result[0] == dataId {
		return true, nil
	}

	return false, nil
}

func md5string(text string) string {
	algorithm := md5.New()
	algorithm.Write([]byte(text))
	return hex.EncodeToString(algorithm.Sum(nil))
}

func hmacSHA1(key string, data string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
