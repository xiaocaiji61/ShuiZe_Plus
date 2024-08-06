
from Plugins.infoGather.webInfo.fingerdata.deal import run_fingermain

def run_getWebInfo(url):
    finger_file = './Plugins/infoGather/webInfo/fingerdata/finger.json'
    # finger_file = './fingerdata/finger.json'

    info = run_fingermain(url, finger_file)

    if info:
        return info

    return ""


if __name__ == '__main__':
    finger_file = './fingerdata/finger.json'
    url = ""

    info = run_fingermain(url, finger_file)
    print("info:{}".format(info))
