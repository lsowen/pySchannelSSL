from ctypes import *
import ctypes
from ctypes.wintypes import *
from binascii import hexlify, unhexlify

CRYPT32 = windll.Crypt32

CERT_SHA1_HASH_PROP_ID = 0x3

X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_FIND_HASH = 0x10000

class CRYPT_HASH_BLOB(Structure):
    _fields_ = [("cbData", DWORD),
                ("pbData", PBYTE)]

def get_certificate_sha1(cert_context):
    func = CRYPT32.CertGetCertificateContextProperty

    output_buffer = create_string_buffer(1024)
    buffer_size = c_int(sizeof(output_buffer))
    prop_id = CERT_SHA1_HASH_PROP_ID

    func(cert_context, prop_id, output_buffer, byref(buffer_size))
    sha1_hash = output_buffer.raw[:buffer_size.value]
    return hexlify(sha1_hash)


def find_certificate_by_sha1(store, sha1_hash):
    sha1_hash = unhexlify(sha1_hash)

    buffer = c_char_p(sha1_hash)
    params = CRYPT_HASH_BLOB()
    params.pbData = cast(buffer, POINTER(c_byte))
    params.cbData = len(sha1_hash)

    func = CRYPT32.CertFindCertificateInStore
    certificate_pointer = c_void_p(func(store.store,
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_HASH,
                                        byref(params),
                                        None))

    return certificate_pointer


def select_client_certificate(store):
    func = windll.Cryptui.CryptUIDlgSelectCertificateFromStore
    certificate_pointer = c_void_p(func(store.store, None, None, None, 0, 0, None))
    # get_certificate_sha1(certificatePointer)
    return certificate_pointer


class CertificateStore(object):
    def __init__(self, name):
        self._name = name
        self.store = CRYPT32.CertOpenSystemStoreW(None, name)

    def __del__(self):
        CRYPT32.CertCloseStore(self.store, 0)
