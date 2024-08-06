import json
import warnings
from urllib.parse import urlparse

import chardet
from bs4 import BeautifulSoup
from collections import Counter

warnings.filterwarnings('ignore')
import requests
import base64
import mmh3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# finger_file = './Plugins/infoGather/webInfo/fingerdata/finger.json'

def get_hash(content):
    def mmh3_hash32(raw_bytes, is_uint32=True):
        h32 = mmh3.hash(raw_bytes)

        if is_uint32:
            return str(h32 & 0xffffffff)
        else:
            return str(h32)

    def stand_base64(braw) -> bytes:
        bckd = base64.standard_b64encode(braw)
        buffer = bytearray()
        for i, ch in enumerate(bckd):
            buffer.append(ch)
            if (i + 1) % 76 == 0:
                buffer.append(ord('\n'))
        buffer.append(ord('\n'))
        return bytes(buffer)

    return mmh3_hash32(stand_base64(content))


def run_fingermain(url, finger_file):
    with open(finger_file, "r", encoding="utf-8") as f:
        finger_data = json.loads(f.read())['fingerprint']

    # print("共加载web指纹：{}条".format(len(finger_data)))

    # location = []
    # method = []
    #
    # for i in finger_data:
    #     location.append(i['location'])
    #     method.append(i['method'])
    #
    # print('method:{}', set(method))
    # print('location:{}', set(location))

    try:
        response = requests.get(url=url, verify=False, timeout=10, allow_redirects=True)
    except:
        return None

    soup = BeautifulSoup(response.text, "html.parser")

    # 解析 URL
    parsed_url = urlparse(url)

    # 获取协议和主机部分
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"

    favicon_url = None
    for link in soup.find_all("link"):
        if "icon" in link.get("rel", []):
            favicon_url = link.get("href")
            break

    web_title = ""
    if soup.title:
        web_title = soup.title.string

    # 获取图标hash
    favicon_hash = ""

    try:
        if favicon_url:
            if "http" not in favicon_url:
                favicon_url = base_url + favicon_url
            # print("favicon_url:{}".format(favicon_url))
            favicon_response = requests.get(favicon_url, verify=False, timeout=10)

            favicon_hash = get_hash(favicon_response.content)
        else:
            favicon_url = base_url + "favicon.ico"
            # print("favicon_url:{}".format(favicon_url))
            favicon_response = requests.get(favicon_url, verify=False, timeout=10)
            favicon_hash = get_hash(favicon_response.content)
    except:
        favicon_hash = ""


    # print("favicon_hash:{}".format(favicon_hash))

    response_header = str(response.headers).replace("'", "")
    # print(type(response_header))
    # print("response_header:{}".format(response_header))

    # 获取网站源码，防止中文乱码

    try:
        cont = response.content
        # 获取网页的编码格式
        charset = chardet.detect(cont)['encoding']
        # 对各种编码情况进行判断
        response_text = cont.decode(charset)
    except Exception:
        response_text = response.text

    # print("response_text:{}".format(response_text))

    info_list = []
    for rule in finger_data:
        # 检查图标hash
        if rule["method"] == "faviconhash" or rule["method"] == "icon_hash" or "hash" in rule['location']:
            for keyword in rule["keyword"]:
                if keyword in favicon_hash:
                    info_list.append(rule['cms'])

        #   检查关键字
        elif rule["method"] == "keyword":
            match_count = 0
            if "body" in rule["location"]:
                for keyword in rule["keyword"]:
                    if keyword in response_text:
                        match_count += 1
            if match_count == len(rule["keyword"]):
                info_list.append(rule['cms'])

            if "header" in rule["location"]:
                match_count = 0
                for keyword in rule["keyword"]:
                    if keyword in response_header:
                        match_count += 1
                if match_count == len(rule["keyword"]):
                    info_list.append(rule['cms'])

            if "title" in rule["location"]:
                match_count = 0

                for keyword in rule["keyword"]:
                    try:
                        if keyword in web_title:
                            match_count += 1
                    except:
                        match_count = 0

                if match_count == len(rule["keyword"]):
                    info_list.append(rule['cms'])

    # 使用Counter统计每个元素的出现次数
    counter = Counter(info_list)

    # 按照出现次数从大到小进行排序
    sorted_items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    # print(sorted_items)

    # 取出前三个元素
    top_three = [item[0] for item in sorted_items[:3]]

    return top_three


if __name__ == '__main__':
    finger_file = 'finger.json'
    url = ""

    info = run_fingermain(url,finger_file)
    print("info:{}".format(info))
