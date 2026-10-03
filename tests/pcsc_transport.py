"""Small Windows PC/SC transport with exact reader selection and typed native calls."""
import ctypes as C
from ctypes import wintypes as W
class PCI(C.Structure):
    _fields_=[('protocol',W.DWORD),('length',W.DWORD)]
class Card:
    def __init__(self,reader):
        self.dll=C.WinDLL('winscard');d=self.dll
        handle=C.c_size_t;ph=C.POINTER(handle)
        specs={'SCardEstablishContext':([W.DWORD,C.c_void_p,C.c_void_p,ph],W.LONG),
        'SCardListReadersW':([handle,W.LPCWSTR,W.LPWSTR,C.POINTER(W.DWORD)],W.LONG),
        'SCardConnectW':([handle,W.LPCWSTR,W.DWORD,W.DWORD,ph,C.POINTER(W.DWORD)],W.LONG),
        'SCardTransmit':([handle,C.POINTER(PCI),C.c_void_p,W.DWORD,C.c_void_p,C.c_void_p,C.POINTER(W.DWORD)],W.LONG),
        'SCardDisconnect':([handle,W.DWORD],W.LONG),'SCardReleaseContext':([handle],W.LONG)}
        for name,(args,res) in specs.items():getattr(d,name).argtypes=args;getattr(d,name).restype=res
        self.ctx=handle();self.h=handle();self.protocol=W.DWORD()
        self.check(d.SCardEstablishContext(0,None,None,C.byref(self.ctx)))
        size=W.DWORD();self.check(d.SCardListReadersW(self.ctx,None,None,C.byref(size)))
        buf=C.create_unicode_buffer(size.value);self.check(d.SCardListReadersW(self.ctx,None,buf,C.byref(size)))
        names=[s for s in buf[:].split('\0') if s]
        matches=[s for s in names if reader==s or (reader=='PCD' and 'PCD' in s)]
        if len(matches)!=1:raise RuntimeError(f'Expected exactly one reader matching {reader!r}: {names}')
        self.reader=matches[0]
        self.check(d.SCardConnectW(self.ctx,self.reader,2,3,C.byref(self.h),C.byref(self.protocol)))
    @staticmethod
    def check(code):
        if code:raise RuntimeError(f'PCSC error {code & 0xffffffff:08x}')
    def transmit(self,cmd):
        cmd=bytes(cmd);send=C.create_string_buffer(cmd);recv=C.create_string_buffer(4096);size=W.DWORD(len(recv))
        pci=PCI(self.protocol.value,C.sizeof(PCI))
        self.check(self.dll.SCardTransmit(self.h,C.byref(pci),send,len(cmd),None,recv,C.byref(size)))
        data=recv.raw[:size.value]
        if len(data)<2:raise RuntimeError('Truncated response')
        return list(data[:-2]),data[-2],data[-1]
    def close(self):
        if self.h.value:self.dll.SCardDisconnect(self.h,0);self.h.value=0
        if self.ctx.value:self.dll.SCardReleaseContext(self.ctx);self.ctx.value=0
if __name__=='__main__':
    c=Card('PCD')
    try:print(c.reader,c.transmit(bytes.fromhex('00a4040006d2760001240100')))
    finally:c.close()
