import ctypes
from ctypes import byref, c_ulong, c_size_t, create_string_buffer, c_void_p

SCARD_SCOPE_USER = 0
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_PROTOCOL_T1 = 2

winscard = ctypes.windll.winscard

def check(ret, msg):
    if ret != 0:
        raise Exception(f"{msg} failed with code 0x{(ret & 0xFFFFFFFF):08X}")

def main():
    print("=" * 60)
    print(" Testing RSA 2048 on SmartPGP")
    print("=" * 60)
    
    hContext = c_size_t()
    check(winscard.SCardEstablishContext(SCARD_SCOPE_USER, None, None, byref(hContext)), "EstablishContext")
    
    cchReaders = c_ulong(0)
    check(winscard.SCardListReadersA(hContext, None, None, byref(cchReaders)), "ListReaders length")
    buf = create_string_buffer(cchReaders.value)
    check(winscard.SCardListReadersA(hContext, None, buf, byref(cchReaders)), "ListReaders")
    readers = [r.decode('ascii') for r in buf.raw.split(b'\x00') if r]
    
    pcd_reader = [r for r in readers if "PCD" in r][0]
    hCard = c_size_t()
    activeProtocol = c_ulong()
    check(winscard.SCardConnectA(hContext, pcd_reader.encode('ascii'), SCARD_SHARE_SHARED, 
                                 SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, byref(hCard), byref(activeProtocol)), "Connect")
    
    pci_name = "g_rgSCardT1Pci" if activeProtocol.value == SCARD_PROTOCOL_T1 else "g_rgSCardT0Pci"
    pci_ptr = byref(c_void_p.in_dll(winscard, pci_name))
    
    def transmit(apdu_hex):
        apdu = bytes.fromhex(apdu_hex)
        recv_buf = create_string_buffer(1024)
        recv_len = c_ulong(len(recv_buf))
        ret = winscard.SCardTransmit(hCard, pci_ptr, apdu, len(apdu), None, recv_buf, byref(recv_len))
        check(ret, f"Transmit {apdu_hex}")
        resp = bytes(recv_buf[:recv_len.value])
        sw = resp[-2:].hex().upper() if len(resp) >= 2 else ""
        data = resp[:-2].hex().upper()
        return data, sw
        
    try:
        # Select
        data, sw = transmit("00A4040006D2760001240100")
        assert sw == "9000" or sw.startswith("61") or sw.startswith("6C")
        
        # Verify Admin PIN
        data, sw = transmit("00200083083132333435363738")
        assert sw == "9000"
        
        # Set Algorithm Attributes for SIG: RSA 2048 (01 08 00 00 11 03)
        print("[*] Setting SIG attribute to RSA 2048...")
        data, sw = transmit("00DA00C106010800001103")
        print(f"    Status: {sw}")
        assert sw == "9000"
        
        # Verify User PIN
        data, sw = transmit("0020008106313233343536")
        assert sw == "9000"
        
        # Generate RSA 2048 key pair for SIG
        print("[*] Generating RSA 2048 Key Pair for SIG...")
        data, sw = transmit("0047800002B60000")
        print(f"    Status: {sw}, PubKey DO len: {len(data)//2} bytes")
        if sw.startswith("61"):
            extra, sw_resp = transmit("00C00000" + sw[2:])
            data += extra
            sw = sw_resp
        assert sw == "9000"
        
        # Sign a PKCS#1 v1.5 padded digest (e.g. SHA-256 DigestInfo prefix + 32-byte digest = 51 bytes)
        # SHA-256 DigestInfo header: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 (19 bytes)
        # + 32 bytes hash = 51 bytes
        digest_info = "3031300D060960864801650304020105000420" + "42" * 32
        lc = f"{(len(digest_info)//2):02X}"
        print(f"[*] Signing with RSA 2048 PKCS#1 v1.5 ({len(digest_info)//2} bytes)...")
        data, sw = transmit("002A9E9A" + lc + digest_info + "00")
        print(f"    Status: {sw}, Signature len: {len(data)//2} bytes")
        assert sw == "9000"
        assert len(data)//2 == 256
        print("--> RSA 2048 sign SUCCESS!")
        
    finally:
        winscard.SCardDisconnect(hCard, 0)
        winscard.SCardReleaseContext(hContext)

if __name__ == "__main__":
    main()
