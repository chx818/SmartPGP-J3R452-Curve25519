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
    print(" Testing NIST P-256 (ansix9p256r1) on SmartPGP")
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
        recv_buf = create_string_buffer(512)
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
        
        # Set Algorithm Attributes for SIG: ECDSA P-256 (13 + OID)
        # OID: 2A 86 48 CE 3D 03 01 07 (8 bytes)
        # Total data: 13 2A 86 48 CE 3D 03 01 07 (9 bytes)
        print("[*] Setting SIG attribute to NIST P-256...")
        data, sw = transmit("00DA00C109132A8648CE3D030107")
        print(f"    Status: {sw}")
        assert sw == "9000"
        
        # Verify User PIN
        data, sw = transmit("0020008106313233343536")
        assert sw == "9000"
        
        # Generate P-256 key pair for SIG
        print("[*] Generating NIST P-256 Key Pair for SIG...")
        data, sw = transmit("0047800002B60000")
        print(f"    Status: {sw}, PubKey DO: {data[:40]}...")
        assert sw == "9000"
        
        # Compute Digital Signature with SHA-256 (32 bytes digest)
        # Digest: 32 bytes of 0x42
        digest = "42" * 32
        print("[*] Signing 32-byte SHA-256 digest with ECDSA P-256...")
        data, sw = transmit("002A9E9A20" + digest)
        print(f"    Status: {sw}, Signature len: {len(data)//2} bytes, Sig: {data}")
        assert sw == "9000"
        print("--> NIST P-256 ECDSA sign SUCCESS!")
        
    finally:
        winscard.SCardDisconnect(hCard, 0)
        winscard.SCardReleaseContext(hContext)

if __name__ == "__main__":
    main()
