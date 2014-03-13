from ctypes import *
import ctypes
from ctypes.wintypes import *

CRYPT32 = windll.Crypt32

class CRYPTUI_SELECTCERTIFICATE_STRUCT(Structure):
    _fields_ = [("dwSize", DWORD),
                ("hwndParent", HANDLE),
                ("dwFlags", DWORD)]

def select_client_certificate(store, options = None):

    if options is None:
        func = windll.Cryptui.CryptUIDlgSelectCertificateFromStore
        certificatePointer = c_void_p(func(store.store, None, None, None, 0, 0, None))    
        return certificatePointer
    else:
        pass
    
class CertificateStore(object):
    def __init__(self, name):
        self._name = name        
        self.store = CRYPT32.CertOpenSystemStoreW(None, name)
        
    def __del__(self):
        CRYPT32.CertCloseStore(self.store, 0)     