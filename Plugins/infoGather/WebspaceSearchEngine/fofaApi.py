import requests
import base64
import json
import configparser
import re

# 域名查询语句domain="xxx.com"
# c段查询语句ip="xxx.xxx.xxx.0/24"
# query = r'domain="xxx.com"'
# query = r'ip="xxx.xxx.xxx.0/24"'

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
secs = cf.sections()
email = cf.get('fofa api', 'EMAIL')
key = cf.get('fofa api', 'KEY')

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

size = 10000
page = 1

# 判断是否是域名
def isdomain(str):
    p = re.compile('^(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\\.)+[a-zA-Z]{2,}$')
    if p.match(str):
        return True
    else:
        return False

def query_ip(c_subnet):
    print('[fofa] 查询：{}'.format(c_subnet))
    return query(c_subnet)


def query_domain(query_str):
    print('[fofa] 查询：{}'.format(query_str))
    return query(query_str)


# 过滤出web服务
def filter_web(result):
    host, title, ip, domain, port, server, protocol, address = result

    # 返回开放http服务的ip和端口
    if 'http' in protocol or protocol == '':
        web_host_port = '{}'.format(host)  # web服务, host是IP:PORT
        return True, web_host_port
    else:  # 其他非web服务
        return False, [protocol, ip, int(port)]


def query(query_str):
    fofa_web_host_port = []  # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    fofa_service_host_port = []  # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测

    qbase64 = str(base64.b64encode(query_str.encode(encoding='utf-8')), 'utf-8')
    url = r'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&size={}&page={}&fields=host,title,ip,domain,port,server,protocol,city'.format(
        email, key, qbase64, size, page)
    try:
        ret = json.loads(requests.get(url=url, headers=headers, timeout=10, verify=False).text)
        fofa_Results = ret['results']
        for result in fofa_Results:
            isWeb, host_port = filter_web(result)
            if isWeb:
                fofa_web_host_port.append(host_port)
            else:
                fofa_service_host_port.append(host_port)
        return fofa_Results, fofa_web_host_port, fofa_service_host_port

    except Exception as e:
        print('[error] fofa 查询 {} : {}'.format(query_str, e.args))
        return [], [], []


# 判断是否是IP
def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


# 判断是否是域名
def isdomain(str):
    p = re.compile('^(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\\.)+[a-zA-Z]{2,}$')
    if p.match(str):
        return True
    else:
        return False


if __name__ == '__main__':
    cf = configparser.ConfigParser()
    cf.read("../../../iniFile/config.ini", encoding="utf-8")
    secs = cf.sections()
    email = cf.get('fofa api', 'EMAIL')
    key = cf.get('fofa api', 'KEY')
    domain = "5112a.co"
    ip = "192.0.78.204"
    subdomainOrIp = ip
    query_str = 'ip="{}"'.format(ip)
    fofa_Results, fofa_web_host_port, fofa_service_host_port = query_ip(query_str)

    if fofa_web_host_port:
        ip2domain_dict = {}
        for each in fofa_web_host_port:
            if isdomain(each):
                tmp_domain = each.split(".")[-2] + "." + each.split(".")[-1]
                if tmp_domain != domain:

                    if subdomainOrIp in ip2domain_dict.keys():

                        ip2domain_dict[subdomainOrIp] = ip2domain_dict[subdomainOrIp] + "," + each
                    else:
                        ip2domain_dict[subdomainOrIp] = each

                    print("fofa:{}反查域名：{}".format(subdomainOrIp, each))

    print(fofa_Results)
    print(fofa_web_host_port)
    print(fofa_service_host_port)
    print(ip2domain_dict)

