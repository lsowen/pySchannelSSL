from sslsocket import SSLSocket
import socket
import errno
from http.client import HTTPConnection, HTTPSConnection
from urllib.request import HTTPSHandler as HTTPSHandlerBase


class SSLConnection(HTTPSConnection):

    def __init__(self, host, port=None, key_data=None, cert_data=None, extra_chain = None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        HTTPConnection.__init__(self, host, port, strict, timeout)

        self.key_data = key_data
        self.cert_data = cert_data
        self.extra_chain = extra_chain


    def connect(self):
        s = socket.create_connection((self.host, self.port))

        if self._tunnel_host:
            self.sock = s
            self._tunnel()

        ssl_sock = SSLSocket(s, server_hostname = self.host)

        self.sock = ssl_sock


class HTTPSHandler(HTTPSHandlerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

    def https_open(self, req):
        def _SSLConnection(host, **kwargs):
            return SSLConnection(host, **kwargs)

        return self.do_open(_SSLConnection, req)