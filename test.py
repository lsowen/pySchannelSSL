import urllib
import urllib.request
import ssl
from httpshandler import HTTPSHandler



target = "https://httpbin.org/post"


def _opener():
    opener = urllib.request.OpenerDirector()
    
    #context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)    
    #opener.add_handler(urllib.request.HTTPSHandler(context = context))
    opener.add_handler(HTTPSHandler())
    
    return opener


def make_request(target, method = 'POST'):
    headers = {}
    o = _opener()
    
    params = {'test': 'HEY'}
    
    request = urllib.request.Request(url = target, headers = headers, data = urllib.parse.urlencode(params).encode('utf8'))


    response = o.open(request)
    response_data = response.read()
    return response_data


print(make_request(target).decode('utf8'))