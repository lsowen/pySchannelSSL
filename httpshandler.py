from .sslsocket import SSLSocket
import socket
import errno
from http.client import HTTPConnection, HTTPSConnection
from urllib.request import HTTPSHandler as HTTPSHandlerBase


class SSLConnection(HTTPSConnection):

    def __init__(self, host, port=None, context = None, client_certificate = None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        HTTPConnection.__init__(self, host, port, strict, timeout)

        self._client_certificate = client_certificate
        self._context = context



    def connect(self):
        s = socket.create_connection((self.host, self.port))

        if self._tunnel_host:
            self.sock = s
            self._tunnel()

        ssl_sock = SSLSocket(s, server_hostname = self.host, client_certificate = self._client_certificate, context = self._context)

        self.sock = ssl_sock


class HTTPSHandler(HTTPSHandlerBase):
    def __init__(self, client_certificate = None, context = None, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self._client_certificate = client_certificate
        self._context = context

    def https_open(self, req):
        def _SSLConnection(host, **kwargs):
            return SSLConnection(host, context = self._context, client_certificate = self._client_certificate, **kwargs)

        return self.do_open(_SSLConnection, req)