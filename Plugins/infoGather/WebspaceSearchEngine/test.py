import requests
import json
API_KEY = 's6QcMzlL1PhHJq9fqE7QXndfTZleO6BG'
query = 'net:"103.9.150.113/24"'
url = 'https://api.shodan.io/shodan/host/search?key='+API_KEY+'&query='+query
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'}
req = requests.get(url=url, headers=headers)

print(req.text)
content = json.loads(req.text)
for i in content['matches']:
    print(i)


