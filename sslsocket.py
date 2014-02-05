from socket import socket
from socket import error as socket_error
import errno

from sslcontext import SSLContext


class SSLSocket(socket):
    
    def __init__(self, sock, *args, server_hostname = None, **kwargs):
        server_side = False
        do_handshake_on_connect = True
        
    
        
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
                self._sslobj = SSLContext()._wrap_socket(self, server_side, server_hostname = server_hostname)
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
    
    def recv_into(self, buffer, nbytes = 0, flags = 0, decrypt = True):
        if decrypt:
            if nbytes == 0:
                nbytes = len(buffer)
            data = self.recv(nbytes, flags)
            length = len(data)
            buffer[:length] = data
            return length
        else:
            return socket.recv_into(self, buffer, nbytes, flags)

    
    def recv(self, buffersize, flags = 0, decrypt = True):
        if decrypt:
            return self._sslobj.recv(buffersize, flags)
        else:
            return socket.recv(self, buffersize, flags)

    
    def sendall(self, data, flags = 0, encrypt = True):
        if encrypt:
            amount = len(data)
            count = 0
            while count < amount:
                v = self.send(data[count:], flags)
                count += v
            return count
        else:
            return socket.sendall(self, data, flags)
    
    def send(self, data, flags=0, encrypt = True):

        if encrypt:
            return self._sslobj.send(data, flags)
        else:
            return socket.send(self, data, flags)
    