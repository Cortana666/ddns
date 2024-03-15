package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func printHelp() {
	fmt.Println("--ip_server 		获取客户端IP的网络服务地址")
	fmt.Println("--ip_server_key 	获取IP服务的响应结构，响应为x.x.x.x字符串即ip地址时传入root，响应为JSON时传入ip地址对应的key（只支持一维JSON）")
	fmt.Println("--dns_server 		DNS解析服务商，CloudFlare传入cf，阿里传入al，腾讯传入tc，NameSilo传入ns， 暂不支持其它")
	fmt.Println("--zone_id		CloudFlare区域ID")
	fmt.Println("--api_token 		CloudFlare区域API令牌")
	fmt.Println("--dns_id 		CloudFlare区域下需修改的解析ID")
	// fmt.Println("--domain		CloudFlare区域下需修改的域名")
}

func initFlag() (string, string, string, string, string, string, string, error) {
	var ipServer string
	var ipServerKey string
	var dnsSever string
	var cfZone string
	var cfToken string
	var cfDnsId string
	var cfDomain string
	// ...

	flag.StringVar(&ipServer, "ip_server", "", "获取客户端IP的网络服务地址")
	flag.StringVar(&ipServerKey, "ip_server_key", "", "获取IP服务的响应结构")
	flag.StringVar(&dnsSever, "dns_server", "", "DNS解析服务商")
	flag.StringVar(&cfZone, "zone_id", "", "区域ID")
	flag.StringVar(&cfToken, "api_token", "", "区域API令牌")
	flag.StringVar(&cfDnsId, "dns_id", "", "DNS解析记录ID")
	flag.StringVar(&cfDomain, "domain", "", "域名")
	// ...
	flag.Parse()

	if ipServer == "" || ipServerKey == "" {
		return "", "", "", "", "", "", "", errors.New("参数错误(1)")
	}

	if dnsSever == "cf" {
		if dnsSever == "" || cfZone == "" || cfToken == "" {
			return "", "", "", "", "", "", "", errors.New("参数错误(3)")
		}
		if (cfDnsId != "" && cfDomain != "") || (cfDnsId == "" && cfDomain == "") {
			return "", "", "", "", "", "", "", errors.New("参数错误(4)")
		}
	} else if dnsSever == "al" {
		return ipServer, ipServerKey, dnsSever, cfZone, cfToken, cfDnsId, cfDomain, nil // ...
	} else if dnsSever == "tc" {
		return ipServer, ipServerKey, dnsSever, cfZone, cfToken, cfDnsId, cfDomain, nil // ...
	} else if dnsSever == "ns" {
		return ipServer, ipServerKey, dnsSever, cfZone, cfToken, cfDnsId, cfDomain, nil // ...
	} else {
		return "", "", "", "", "", "", "", errors.New("参数错误(2)")
	}

	return ipServer, ipServerKey, dnsSever, cfZone, cfToken, cfDnsId, cfDomain, nil // ...
}

func getClientIp(ipServer string, ipServerKey string) (string, error) {
	resp, err := http.Get(ipServer)
	if err != nil {
		return "", errors.New("获取IP失败(1)：" + err.Error())
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("获取IP失败(2)：" + err.Error())
	}

	if ipServerKey == "root" {
		resp := string(body)
		if len(resp) < 7 {
			return "", errors.New("获取IP失败(3)：IP地址错误")
		}
		return string(body), nil
	} else {
		resp := make(map[string]interface{})
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return "", errors.New("获取IP失败(3)：" + err.Error())
		}

		if len(resp[ipServerKey].(string)) < 7 {
			return "", errors.New("获取IP失败(4)：IP地址错误")
		}

		return resp[ipServerKey].(string), nil
	}
}

func checkIpChange(ip string) error {
	_, err := os.Stat("ip.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return errors.New("文件打开错误：" + err.Error())
		}
	}

	file, err := os.Open("ip.txt")
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
		return errors.New("更改DNS解析失败(7)：IP未变更")
	}

	return nil
}

func saveIp(ip string) error {
	file, err := os.Create("ip.txt")
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

func cloudFlareDnsIpEdit(ip string, cfZone string, cfToken string, cfDnsId string, cfDomain string) error {

	// req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones/"+cfZone+"/dns_records", nil)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败(1)：" + err.Error())
	// }
	// req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", "Bearer "+cfToken)
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败(2)：" + err.Error())
	// }
	// defer resp.Body.Close()
	// respBodyBytes, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败(3)：" + err.Error())
	// }
	// respBody := make(map[string]interface{})
	// err = json.Unmarshal(respBodyBytes, &respBody)
	// if err != nil {
	// 	return errors.New("查询DNS解析记录失败(4)：" + err.Error())
	// }
	// if respBody["success"] != true {
	// 	return errors.New("查询DNS解析记录失败(5)：" + (respBody["errors"].([]interface{})[0]).(map[string]interface{})["message"].(string))
	// }

	// cfDnsId := ""

	reqBody := map[string]interface{}{
		"content": ip,
		"name":    "openwrt",
		"type":    "A",
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.New("更改DNS解析失败(1)：" + err.Error())
	}
	reader := bytes.NewReader(reqBodyBytes)
	req, err := http.NewRequest("PATCH", "https://api.cloudflare.com/client/v4/zones/"+cfZone+"/dns_records/"+cfDnsId, reader)
	if err != nil {
		return errors.New("更改DNS解析失败(2)：" + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+cfToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("更改DNS解析失败(3)：" + err.Error())
	}
	defer resp.Body.Close()
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("更改DNS解析失败(4)：" + err.Error())
	}
	respBody := make(map[string]interface{})
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		return errors.New("更改DNS解析失败(5)：" + err.Error())
	}
	if respBody["success"] != true {
		return errors.New("更改DNS解析失败(6)：" + (respBody["errors"].([]interface{})[0]).(map[string]interface{})["message"].(string))
	}

	return nil
}

func main() {
	ipServer, ipServerKey, dnsSever, cfZone, cfToken, cfDnsId, cfDomain, err := initFlag()
	if err != nil {
		fmt.Println(err)
		printHelp()
		return
	}

	ip, err := getClientIp(ipServer, ipServerKey)
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
		err = cloudFlareDnsIpEdit(ip, cfZone, cfToken, cfDnsId, cfDomain)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if dnsSever == "al" {
		fmt.Println("敬请期待")
		return
	}
	if dnsSever == "tc" {
		fmt.Println("敬请期待")
		return
	}
	if dnsSever == "ns" {
		fmt.Println("敬请期待")
		return
	}

	fmt.Println("更改DNS解析成功")

	saveIp(ip)
}
