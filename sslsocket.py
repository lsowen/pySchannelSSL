from socket import socket
from socket import error as socket_error
import errno

from .sslcontext import SSLContext


class SSLSocket(socket):
    
    def __init__(self, sock, server_hostname = None, client_certificate = None, context = None, **kwargs):
        server_side = False
        do_handshake_on_connect = True
        
        self._client_certificate = client_certificate
        self._sslobj = context
    
        
        connected = False
        if sock is not None:
            socket.__init__(self,
                            family=sock.family,
                            type=sock.type,
                            proto=sock.proto,
                            fileno=sock.fileno())
            self.settimeout(sock.gettimeout())
            
            # see if it's connected
            try:
                sock.getpeername()
            except socket_error as e:
                if e.errno != errno.ENOTCONN:
                    raise
            else:
                connected = True
            sock.detach()
            
            
        self._connected = connected
        if connected:
            try:
                if self._sslobj is None:
                    self._sslobj = SSLContext()                    
                self._sslobj._wrap_socket(self, server_side, server_hostname = server_hostname, client_certificate = self._client_certificate)
                
                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError("do_handshake_on_connect should not be specified for non-blocking sockets")
                    self.do_handshake()                
            except socket_error as x:
                self.close()
                raise x
    
    def do_handshake(self, block=False):
        """Perform a TLS/SSL handshake."""

        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
            self._sslobj.do_handshake()
        finally:
            self.settimeout(timeout)        
    
    def recv_into(self, buffer, nbytes = 0, flags = 0, raw = False):
        if not raw:
            if nbytes == 0:
                nbytes = len(buffer)
            data = self.recv(nbytes, flags)
            length = len(data)
            buffer[:length] = data
            return length
        else:
            return socket.recv_into(self, buffer, nbytes, flags)

    
    def recv(self, buffersize, flags = 0, raw = False):
        if not raw:
            data = self._sslobj.recv(buffersize, flags)
            #print("RECV: {0}".format(data))
            return data
        else:
            data = socket.recv(self, buffersize, flags)
            #print("RECV (raw): {0}".format(data))
            return data

    
    def sendall(self, data, flags = 0, raw = False):
        amount = len(data)
        count = 0
        while count < amount:
            v = self.send(data[count:], flags, raw)
            count += v
        return count
        
        if not raw:
            amount = len(data)
            count = 0
            while count < amount:
                v = self.send(data[count:], flags)
                count += v
            return count
        else:
            return socket.sendall(self, data, flags)
    
    def send(self, data, flags=0, raw = False):
        if not raw:
            #print("Send: {0}".format(data))
            return self._sslobj.send(data, flags)
        else:
            #print("Send (Raw): {0}".format(data))
            return socket.send(self, data, flags)
    