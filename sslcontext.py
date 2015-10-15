from ctypes import *
import ctypes
from ctypes.wintypes import *

from _ssl import SSLError

import sys

CRYPT32 = windll.Crypt32
SCHANNEL = windll.SChannel

# Lots of "Magic" constants, mainly from schannel.h

SCH_CRED_NO_SYSTEM_MAPPER = 0x00000002
SCH_CRED_NO_DEFAULT_CREDS = 0x00000010
SCH_CRED_REVOCATION_CHECK_CHAIN = 0x00000200

SECPKG_ATTR_REMOTE_CERT_CONTEXT = 0x53
SECPKG_ATTR_STREAM_SIZES = 4

SP_PROT_SSL3_CLIENT = 0x00000020
SP_PROT_SSL2_CLIENT = 0x00000008
SP_PROT_TLS1_1_CLIENT = 0x00000200


SCHANNEL_CRED_VERSION = 0x00000004

UNISP_NAME = "Microsoft Unified Security Protocol Provider"


SECPKG_CRED_OUTBOUND = 0x00000002
SECURITY_NATIVE_DREP = 0x00000010

SECBUFFER_VERSION = 0
SECBUFFER_EMPTY = 0
SECBUFFER_DATA = 1
SECBUFFER_TOKEN = 2
SECBUFFER_EXTRA = 5
SECBUFFER_STREAM_TRAILER = 6
SECBUFFER_STREAM_HEADER = 7


ISC_REQ_SEQUENCE_DETECT = 0x00000008
ISC_REQ_REPLAY_DETECT = 0x00000004
ISC_REQ_CONFIDENTIALITY = 0x00000010
ISC_REQ_EXTENDED_ERROR = 0x00008000
ISC_REQ_ALLOCATE_MEMORY = 0x00000100
ISC_REQ_STREAM = 0x00010000

SEC_I_CONTINUE_NEEDED = 0x00090312
SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320
SEC_I_RENEGOTIATE = 0x00090321
SEC_E_INCOMPLETE_MESSAGE = 0x80090318
SEC_E_INTERNAL_ERROR = 0x80090304
SEC_E_OK = 0x00000000

class SecPkgContext_StreamSizes(Structure):
    _fields_ = [("cbHeader", ULONG),
                ("cbTrailer", ULONG),
                ("cbMaximumMessage", ULONG),
                ("cBuffers", ULONG),
                ("cbBlockSize", ULONG)]

class CERT_CONTEXT(Structure):
    _fields_ = [("dwCertEncodingType", DWORD),
                ("pbCertEncoded", c_char_p),
                ("cbCertEncoded", DWORD),
                ("pCertInfo", c_void_p),
                ("hCertStore", c_void_p)]

class SecBuffer(Structure):
    _fields_ = [("cbBuffer", ULONG),
                ("BufferType", ULONG),
                ("pvBuffer", c_void_p)]

class SecBufferDesc(Structure):
    _fields_ = [("ulVersion", ULONG),
                ("cBuffers", ULONG),
                ("pBuffers", POINTER(SecBuffer))]

class _SecHandle(Structure):
    _fields_ = [("dwLower", ULONG ),
                ("dwUpper", ULONG )]

class SCHANNEL_CRED(Structure):
    _fields_ = [("dwVersion", DWORD),
                ("cCreds", DWORD),
                ("paCred", POINTER(HANDLE)),
                ("hRootStore", HANDLE),
                ("cMappers", DWORD),
                ("aphMappers", POINTER(HANDLE)),
                ("cSupportedAlgs", DWORD),
                ("palgSupportedAlgs", POINTER(HANDLE)),
                ("grbitEnabledProtocols", DWORD),
                ("dwMinimumCipherStrength", DWORD),
                ("dwMaximumCipherStrength", DWORD),
                ("dwSessionLifespan", DWORD),
                ("dwFlags", DWORD),
                ("dwCredFormat", DWORD),
                ]

class SecurityFunctionTable(Structure):
    _fields_ = [("dwVersion", ULONG),
                ("EnumerateSecurityPackages", WINFUNCTYPE(LONG)),
                ("QueryCredentialsAttributes", WINFUNCTYPE(LONG)),
                ("AcquireCredentialsHandle", WINFUNCTYPE(ULONG, c_void_p, c_wchar_p, ULONG, HANDLE, c_void_p, c_void_p, c_void_p, HANDLE, PULONG)),
                ("FreeCredentialsHandle", WINFUNCTYPE(LONG)),
                ("Reserved2", c_void_p),
                ("InitializeSecurityContext", WINFUNCTYPE(ULONG, c_void_p, c_void_p, c_wchar_p, ULONG, ULONG, ULONG, c_void_p, ULONG, c_void_p, c_void_p, POINTER(ULONG), POINTER(ULONG))),
                ("AcceptSecurityContext", WINFUNCTYPE(ULONG)),
                ("CompleteAuthToken", WINFUNCTYPE(LONG)),
                ("DeleteSecurityContext", WINFUNCTYPE(LONG, c_void_p)),
                ("ApplyControlToken", WINFUNCTYPE(LONG)),
                ("QueryContextAttributes", WINFUNCTYPE(LONG, c_void_p, ULONG, c_void_p)),
                ("ImpersonateSecurityContext", WINFUNCTYPE(LONG)),
                ("RevertSecurityContext", WINFUNCTYPE(LONG)),
                ("MakeSignature", WINFUNCTYPE(LONG)),
                ("VerifySignature", WINFUNCTYPE(LONG)),
                ("FreeContextBuffer", WINFUNCTYPE(LONG, c_void_p)),
                ("QuerySecurityPackageInfo", WINFUNCTYPE(LONG)),
                ("Reserved3", c_void_p),
                ("Reserved4", c_void_p),
                ("ExportSecurityContext", WINFUNCTYPE(LONG)),
                ("ImportSecurityContext", WINFUNCTYPE(LONG)),
                ("AddCredentials", WINFUNCTYPE(LONG)),
                ("Reserved8", c_void_p),
                ("QuerySecurityContextToken", WINFUNCTYPE(LONG)),
                ("EncryptMessage", WINFUNCTYPE(ULONG, HANDLE, ULONG, HANDLE, ULONG)),
                ("DecryptMessage", WINFUNCTYPE(ULONG, HANDLE, HANDLE, ULONG, PULONG)),
                ("SetContextAttributes", WINFUNCTYPE(LONG)),]

class SSLContext(object):

    def __init__(self):
        self._InitSecurityInterface()
        self._creds = None
        self._context = _SecHandle()

        self._SchannelCred = None
        self._intialized = False
        self._recv_buffer = b'' # Raw socket data
        self._recv_buffer_decrypted = b'' # socket data that is decrypted

        self.reset()

    def reset(self):
        if self._creds is not None:
            windll.Secur32.FreeCredentialsHandle(byref(self._creds))

        self._creds = _SecHandle()
        self._creds.dwUpper = 0
        self._creds.dwLower = 0

        self._context.dwUpper = 0
        self._context.dwLower = 0

        self._SchannelCred = SCHANNEL_CRED()

        self._intialized = False
        self._recv_buffer = b'' # Raw socket data
        self._recv_buffer_decrypted = b'' # socket data that is decrypted


    def do_handshake(self):
        self.reset()
        self._ClientCreateCredentials()
        self._ClientHandshake()
        #TODO: validate remote certificate

        self._intialized = True #all communications should now be encrypted

    def _ClientHandshake(self):
        buffer = SecBuffer()
        buffer.pvBuffer = None
        buffer.BufferType = SECBUFFER_TOKEN
        buffer.cbBuffer = 0

        bufferGroup = SecBufferDesc()
        bufferGroup.cBuffers = 1
        bufferGroup.pBuffers = pointer(buffer)
        bufferGroup.ulVersion = SECBUFFER_VERSION


        dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM

        dwSSPIOutFlags = DWORD()

        Status = self._securityFunc.InitializeSecurityContext(byref(self._creds),
                                                              None,
                                                              c_wchar_p(self._server_hostname),
                                                              dwSSPIFlags,
                                                              0,
                                                              SECURITY_NATIVE_DREP,
                                                              None,
                                                              0,
                                                              byref(self._context),
                                                              byref(bufferGroup),
                                                              byref(dwSSPIOutFlags),
                                                              POINTER(ULONG)() )

        if Status != SEC_I_CONTINUE_NEEDED and Status != SEC_E_OK:
            raise SSLError(WinError(c_long(Status).value))

        if Status == SEC_I_CONTINUE_NEEDED:

            if buffer.cbBuffer != 0 and buffer.pvBuffer is not None:
                data = string_at(buffer.pvBuffer, buffer.cbBuffer)
                if self.send(data, plaintext = True) == 0:
                    self._securityFunc.FreeContextBuffer(buffer.pvBuffer)
                    self._securityFunc.DeleteSecurityContext(byref(self._context))

                else:
                    self._securityFunc.FreeContextBuffer(buffer.pvBuffer)

            (Status,extraData) = self._ClientHandshakeLoop(True)


        if Status != SEC_E_OK:
            raise SSLError(WinError(c_long(Status).value))

    def _ClientHandshakeLoop(self, doRead):
        Status = SEC_I_CONTINUE_NEEDED

        dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM

        dwSSPIOutFlags = DWORD()

        recv_data = b''

        while Status == SEC_I_CONTINUE_NEEDED or Status == SEC_E_INCOMPLETE_MESSAGE or Status == SEC_I_INCOMPLETE_CREDENTIALS:

            if len(recv_data) == 0 or Status == SEC_E_INCOMPLETE_MESSAGE:
                if doRead:
                    data = self._sock.recv(2048, raw = True)
                    recv_data += data
                else:
                    doRead = True


            inBufferGroup = SecBufferDesc()
            inBufferGroup.cBuffers = 2
            inBufferGroup.ulVersion = SECBUFFER_VERSION


            buffers = (SecBuffer * 2)()
            buffers[0].pvBuffer = cast(c_char_p(recv_data), c_void_p)
            buffers[0].cbBuffer = len(recv_data)
            buffers[0].BufferType = SECBUFFER_TOKEN

            buffers[1].pvBuffer = None
            buffers[1].cbBuffers = 0
            buffers[1].BufferType = SECBUFFER_EMPTY

            inBufferGroup.pBuffers = buffers

            outBufferGroup = SecBufferDesc()
            outBufferGroup.cBuffers = 1
            outBufferGroup.ulVersion = SECBUFFER_VERSION

            buffers = (SecBuffer * 1)()
            buffers[0].pvBuffer = None
            buffers[0].BufferType = SECBUFFER_TOKEN
            buffers[0].cbBuffer = 0

            outBufferGroup.pBuffers = buffers

            Status = self._securityFunc.InitializeSecurityContext(byref(self._creds),
                                                                  byref(self._context),
                                                                  c_wchar_p(self._server_hostname),
                                                                  dwSSPIFlags,
                                                                  0,
                                                                  SECURITY_NATIVE_DREP,
                                                                  byref(inBufferGroup),
                                                                  0,
                                                                  None,
                                                                  byref(outBufferGroup),
                                                                  byref(dwSSPIOutFlags),
                                                                  POINTER(ULONG)()
                                                                  )


            if Status == SEC_E_OK or Status == SEC_I_CONTINUE_NEEDED:
                if outBufferGroup.pBuffers[0].cbBuffer != 0 and outBufferGroup.pBuffers[0].pvBuffer is not None:
                    data = string_at(outBufferGroup.pBuffers[0].pvBuffer, outBufferGroup.pBuffers[0].cbBuffer)
                    if self._sock.sendall(data, raw = True) == 0:
                        self._securityFunc.FreeContextBuffer(outBufferGroup.pBuffers[0].pvBuffer)
                        self._securityFunc.DeleteSecurityContext(byref(self._context))
                        return (SEC_E_INTERNAL_ERROR, None)
                    else:
                        self._securityFunc.FreeContextBuffer(outBufferGroup.pBuffers[0].pvBuffer)
                        outBufferGroup.pBuffers[0].pvBuffer = None

            if Status == SEC_E_INCOMPLETE_MESSAGE:
                continue

            if Status == SEC_E_OK:
                if inBufferGroup.pBuffers[1].BufferType == SECBUFFER_EXTRA:
                    return (Status, recv_data[-inBufferGroup.pBuffers[1].cbBuffer:])
                else:
                    return (Status, None)

            if inBufferGroup.pBuffers[1].BufferType == SECBUFFER_EXTRA:
                recv_data = recv_data[-inBufferGroup.pBuffers[1].cbBuffer:]
            else:
               recv_data = b""

            if Status == SEC_I_INCOMPLETE_CREDENTIALS:
                #return (Status, None)
                doRead = False
                continue

        return (Status, None)

    def _InitSecurityInterface(self):
        func = SCHANNEL.InitSecurityInterfaceW
        func.restype = POINTER(SecurityFunctionTable)
        self._securityFunc = func().contents


    def _wrap_socket(self, sock, server_side, server_hostname, client_certificate=None):
        self._sock = sock
        self._server_hostname = server_hostname
        self._client_certificate = client_certificate

        return self

    def _ClientCreateCredentials(self):

        if self._client_certificate is not None:
            self._SchannelCred.cCreds = 1
            self._SchannelCred.paCred = pointer(self._client_certificate)

        self._SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT #| SP_PROT_TLS1_1_CLIENT | SP_PROT_SSL2_CLIENT
        self._SchannelCred.dwVersion = SCHANNEL_CRED_VERSION
        self._SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN

        Status = self._securityFunc.AcquireCredentialsHandle(None,
                                                             c_wchar_p(UNISP_NAME),
                                                             SECPKG_CRED_OUTBOUND,
                                                             None,
                                                             byref(self._SchannelCred),
                                                             None,
                                                             None,
                                                             byref(self._creds),
                                                             POINTER(ULONG)())

        if Status != SEC_E_OK:
            raise SSLError(WinError(Status))

    def send(self, data, flags = 0, plaintext = False):
        if self._intialized is False and plaintext is True:
            return self._sock.sendall(data, flags, raw = True)
        else:
            Sizes = SecPkgContext_StreamSizes()
            Status = self._securityFunc.QueryContextAttributes(byref(self._context), SECPKG_ATTR_STREAM_SIZES, byref(Sizes))
            if Status != SEC_E_OK:
                raise SSLError(WinError(c_long(Status).value))


            bufferValue = b'\x00' * Sizes.cbHeader + data + b'\x00' * Sizes.cbTrailer + (b'\x00' *(Sizes.cbMaximumMessage - len(data)))
            allocatedBuffer = create_string_buffer(bufferValue)

            messageBuffers = SecBufferDesc()
            messageBuffers.cBuffers = 4
            messageBuffers.ulVersion = SECBUFFER_VERSION

            buffers = (SecBuffer * 4)()

            buffers[0].BufferType = SECBUFFER_STREAM_HEADER
            buffers[0].cbBuffer = Sizes.cbHeader
            buffers[0].pvBuffer = cast(byref(allocatedBuffer), c_void_p)

            buffers[1].BufferType = SECBUFFER_DATA
            buffers[1].cbBuffer = len(data)
            buffers[1].pvBuffer = cast(byref(allocatedBuffer, Sizes.cbHeader), c_void_p)

            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER
            buffers[2].cbBuffer = Sizes.cbTrailer
            buffers[2].pvBuffer = cast(byref(allocatedBuffer, Sizes.cbHeader + len(data)), c_void_p)

            buffers[3].BufferType = SECBUFFER_EMPTY

            messageBuffers.pBuffers = buffers

            Status = self._securityFunc.EncryptMessage(byref(self._context),0, byref(messageBuffers), 0)

            if Status != SEC_E_OK:
                raise SSLError(WinError(c_long(Status).value))

            encrypted_data = string_at(buffers[0].pvBuffer, buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer)

            return self._sock.sendall(encrypted_data, flags, raw = True)


    def recv(self, buffersize, flags=0, plaintext = False):

        if self._intialized is False and plaintext is True:
            return self._sock.recv(buffersize, flags, raw = True)
        else:

            if len(self._recv_buffer_decrypted) > 0:
                decrypted_data = self._recv_buffer_decrypted[:buffersize]
                self._recv_buffer_decrypted = self._recv_buffer_decrypted[buffersize:]
                return decrypted_data

            decrypted_data = self._recv_buffer_decrypted
            shouldContinue = True
            while shouldContinue:
                self._recv_buffer += self._sock.recv(buffersize, flags, raw = True)


                messageBuffers = SecBufferDesc()
                messageBuffers.cBuffers = 4
                messageBuffers.ulVersion = SECBUFFER_VERSION

                buffers = (SecBuffer * 4)()
                buffers[0].pvBuffer = cast(c_char_p(self._recv_buffer), c_void_p)
                buffers[0].cbBuffer = len(self._recv_buffer)
                buffers[0].BufferType = SECBUFFER_DATA


                buffers[1].BufferType = SECBUFFER_EMPTY
                buffers[2].BufferType = SECBUFFER_EMPTY
                buffers[3].BufferType = SECBUFFER_EMPTY

                messageBuffers.pBuffers = buffers
                Status = self._securityFunc.DecryptMessage(byref(self._context), byref(messageBuffers), 0, None)

                if Status == SEC_E_INCOMPLETE_MESSAGE:
                    continue

                if Status != SEC_E_OK and Status != SEC_I_RENEGOTIATE:
                    raise SSLError(WinError(c_long(Status).value))

                for idx in range(1,4):
                    if messageBuffers.pBuffers[idx].BufferType == SECBUFFER_DATA:
                        decrypted_data += string_at(messageBuffers.pBuffers[idx].pvBuffer, messageBuffers.pBuffers[idx].cbBuffer)
                        break

                extra_data = b''
                for idx in range(1,4):
                    if messageBuffers.pBuffers[idx].BufferType == SECBUFFER_EXTRA:
                        extra_data = string_at(messageBuffers.pBuffers[idx].pvBuffer, messageBuffers.pBuffers[idx].cbBuffer)
                        break

                if len(extra_data) > 0:
                    self._recv_buffer = extra_data
                    continue
                else:
                    self._recv_buffer = b''
                    shouldContinue = False

                if Status == SEC_I_RENEGOTIATE:
                    (Status, _) = self._ClientHandshakeLoop(doRead = False)
                    shouldContinue = True
                    if Status != SEC_E_OK:
                        raise SSLError(WinError(c_long(Status).value))
                elif Status != SEC_E_OK:
                    raise SSLError(WinError(c_long(Status).value))


            self._recv_buffer_decrypted = decrypted_data[buffersize:]
            return decrypted_data[:buffersize]

