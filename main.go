package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var ipServer string
var ipServerKey string
var dnsSever string
var zoneId string
var apiKey string
var apiSecret string
var dnsId string
var hostRecord string
var domain string

func printHelp() {
	fmt.Println("--ip_server 		获取客户端IP的网络服务地址")
	fmt.Println("--ip_server_key 	获取IP服务的响应结构，响应为x.x.x.x字符串即ip地址时传入root，响应为JSON时传入ip地址对应的key（只支持一维JSON）")
	fmt.Println("--dns_server 		DNS解析服务商，CloudFlare传入cf，阿里传入al，腾讯传入tc，NameSilo传入ns， 暂不支持其它")
	fmt.Println("--dns_id 		DNS解析记录ID")
	fmt.Println("--host_record		主机记录")
	fmt.Println("--api_key 		API令牌")
	fmt.Println("--zone_id		CloudFlare区域ID")
	fmt.Println("--api_secret 		API密钥")
	fmt.Println("--domain 		腾讯云DNS解析二级域名")
}

func initFlag() error {
	flag.StringVar(&ipServer, "ip_server", "", "获取客户端IP的网络服务地址")
	flag.StringVar(&ipServerKey, "ip_server_key", "", "获取IP服务的响应结构")
	flag.StringVar(&dnsSever, "dns_server", "", "DNS解析服务商")
	flag.StringVar(&dnsId, "dns_id", "", "DNS解析记录ID")
	flag.StringVar(&hostRecord, "host_record", "", "主机记录")
	flag.StringVar(&apiKey, "api_key", "", "API令牌")
	flag.StringVar(&zoneId, "zone_id", "", "CloudFlare区域ID")
	flag.StringVar(&apiSecret, "api_secret", "", "API密钥")
	flag.StringVar(&domain, "domain", "", "腾讯云DNS解析二级域名")

	flag.Parse()

	if ipServer == "" || ipServerKey == "" || dnsSever == "" || dnsId == "" || hostRecord == "" {
		return errors.New("参数错误：ip_server、ip_server_key、dns_server、dns_id、host_record必填")
	}

	if dnsSever == "cf" {
		if zoneId == "" || apiKey == "" {
			return errors.New("参数错误：CloudFlare下zone_id、api_key必填")
		}
	} else if dnsSever == "al" {
		if apiKey == "" || apiSecret == "" {
			return errors.New("参数错误：Aliyun下api_key、api_secret必填")
		}
	} else if dnsSever == "tc" {
		if apiKey == "" || apiSecret == "" || domain == "" {
			return errors.New("参数错误：Aliyun下api_key、api_secret、domain必填")
		}
	} else if dnsSever == "ns" {
		return nil // ...
	} else {
		return errors.New("参数错误：dns_server填写不正确")
	}

	return nil // ...
}

func getClientIpv4() (string, error) {
	resp, err := http.Get(ipServer)
	if err != nil {
		return "", errors.New("获取IP失败：" + err.Error())
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("获取IP失败：" + err.Error())
	}

	if ipServerKey == "root" {
		resp := string(body)
		if len(resp) < 7 || len(resp) > 15 {
			return "", errors.New("获取IP失败：IP地址错误")
		}
		return string(body), nil
	} else {
		resp := make(map[string]interface{})
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return "", errors.New("获取IP失败：" + err.Error())
		}

		if len(resp[ipServerKey].(string)) < 7 {
			return "", errors.New("获取IP失败：IP地址错误")
		}

		return resp[ipServerKey].(string), nil
	}
}

func checkIpChange(ip string) error {
	_, err := os.Stat("tmp/" + dnsId + ".txt")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return errors.New("文件打开错误：" + err.Error())
		}
	}

	file, err := os.Open("tmp/" + dnsId + ".txt")
	if err != nil {
		return errors.New("文件打开错误：" + err.Error())
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return errors.New("文件获取信息失败：" + err.Error())
	}

	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)
	_, err = file.Read(buffer)
	if err != nil {
		return errors.New("文件读取失败：" + err.Error())
	}

	if string(buffer) == ip {
		return errors.New("更改DNS解析失败：IP未变更")
	}

	return nil
}

func saveIp(ip string) error {
	_, err := os.Stat("tmp/")
	if err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir("tmp", 0755)
			if err != nil {
				return errors.New("文件创建失败：" + err.Error())
			}
			return nil
		} else {
			return errors.New("文件打开错误：" + err.Error())
		}
	}

	file, err := os.Create("tmp/" + dnsId + ".txt")
	if err != nil {
		return errors.New("文件创建失败：" + err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(ip)
	if err != nil {
		return errors.New("文件写入失败：" + err.Error())
	}

	return nil
}

func cloudFlareDnsIpEdit(ip string) error {

	// req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones/"+zoneId+"/dns_records", nil)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败：" + err.Error())
	// }
	// req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", "Bearer "+key)
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败：" + err.Error())
	// }
	// defer resp.Body.Close()
	// respBodyBytes, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败：" + err.Error())
	// }
	// respBody := make(map[string]interface{})
	// err = json.Unmarshal(respBodyBytes, &respBody)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败：" + err.Error())
	// }
	// if respBody["success"] != true {
	// 	return errors.New("查询DNS解析记录失败：" + (respBody["errors"].([]interface{})[0]).(map[string]interface{})["message"].(string))
	// }

	// dnsId := ""

	reqBody := map[string]interface{}{
		"content": ip,
		"name":    hostRecord,
		"type":    "A",
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	reader := bytes.NewReader(reqBodyBytes)
	req, err := http.NewRequest("PATCH", "https://api.cloudflare.com/client/v4/zones/"+zoneId+"/dns_records/"+dnsId, reader)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+apiKey)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	respBody := make(map[string]interface{})
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	if respBody["success"] != true {
		return errors.New("更改DNS解析失败：" + (respBody["errors"].([]interface{})[0]).(map[string]interface{})["message"].(string))
	}

	return nil
}

func aliyunSignature(reqBody map[string]interface{}) string {
	queryParams := url.Values{}
	for key, value := range reqBody {
		queryParams.Set(key, value.(string))
	}
	CanonicalizedQueryString := queryParams.Encode()
	stringToSign := "POST&" + url.QueryEscape("/") + "&" + url.QueryEscape(CanonicalizedQueryString)

	hmacSha1 := hmac.New(sha1.New, []byte(apiSecret+"&"))
	hmacSha1.Write([]byte(stringToSign))
	hmacSignature := hmacSha1.Sum(nil)
	base64Encoded := base64.StdEncoding.EncodeToString(hmacSignature)

	return base64Encoded
}

func aliyunDnsIpEdit(ip string) error {
	reqBody := map[string]interface{}{
		"AccessKeyId":      apiKey,
		"Action":           "UpdateDomainRecord",
		"Format":           "JSON",
		"RecordId":         dnsId,
		"RR":               hostRecord,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   strconv.Itoa(rand.Intn(99999999999999-10000000000000+1) + 10000000000000),
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Type":             "A",
		"Value":            ip,
		"Version":          "2015-01-09",
	}
	reqBody["Signature"] = aliyunSignature(reqBody)
	formData := url.Values{}
	for key, value := range reqBody {
		formData.Set(key, value.(string))
	}
	resp, err := http.Post("http://alidns.aliyuncs.com", "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	respBody := make(map[string]interface{})
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	if resp.StatusCode != 200 {
		return errors.New("更改DNS解析失败：" + respBody["Message"].(string))
	}

	return nil
}

func tencentSignature(reqBody map[string]interface{}) string {
	queryParams := url.Values{}
	for key, value := range reqBody {
		queryParams.Set(key, value.(string))
	}
	CanonicalizedQueryString := queryParams.Encode()
	stringToSign := "POSTdnspod.tencentcloudapi.com/?" + CanonicalizedQueryString

	hmacSha1 := hmac.New(sha1.New, []byte(apiSecret))
	hmacSha1.Write([]byte(stringToSign))
	hmacSignature := hmacSha1.Sum(nil)
	base64Encoded := base64.StdEncoding.EncodeToString(hmacSignature)

	return base64Encoded
}

func tencentDnsIpEdit(ip string) error {
	reqBody := map[string]interface{}{
		"Action":     "ModifyRecord",
		"Domain":     domain,
		"Nonce":      strconv.Itoa(rand.Intn(99999999999999-10000000000000+1) + 10000000000000),
		"RecordType": "A",
		"RecordId":   dnsId,
		"RecordLine": "默认",
		"SecretId":   apiKey,
		"SubDomain":  hostRecord,
		"Timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
		"Value":      ip,
		"Version":    "2021-03-23",
	}
	reqBody["Signature"] = tencentSignature(reqBody)
	formData := url.Values{}
	for key, value := range reqBody {
		formData.Set(key, value.(string))
	}
	resp, err := http.Post("https://dnspod.tencentcloudapi.com", "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	respBody := make(map[string]interface{})
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		return errors.New("更改DNS解析失败：" + err.Error())
	}
	if _, ok := respBody["Response"].(map[string]interface{})["Error"]; ok {
		return errors.New("更改DNS解析失败：" + respBody["Response"].(map[string]interface{})["Error"].(map[string]interface{})["Message"].(string))
	}

	return nil
}

func main() {
	err := initFlag()
	if err != nil {
		fmt.Println(err)
		printHelp()
		return
	}

	ip, err := getClientIpv4()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = checkIpChange(ip)
	if err != nil {
		fmt.Println(err)
		return
	}

	if dnsSever == "cf" {
		err = cloudFlareDnsIpEdit(ip)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if dnsSever == "al" {
		err = aliyunDnsIpEdit(ip)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if dnsSever == "tc" {
		err = tencentDnsIpEdit(ip)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if dnsSever == "ns" {
		fmt.Println("敬请期待")
		return
	}

	fmt.Println("更改DNS解析成功：当前IP为" + ip)

	err = saveIp(ip)
	if err != nil {
		fmt.Println(err)
		return
	}
}
