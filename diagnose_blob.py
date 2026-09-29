#!/usr/bin/env python3
"""
Diagnose the serialization format of a base64-encoded .NET object.
Tries: zlib, gzip, BinaryFormatter, WCF binary XML, raw XML, raw bytes inspection.

Usage: python3 diagnose_blob.py blob.txt
"""

import sys
import base64
import zlib
import gzip
import io

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 diagnose_blob.py <file_with_base64>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        b64 = f.read().strip()

    # Clean up any whitespace/newlines in base64
    b64 = b64.replace("\n", "").replace("\r", "").replace(" ", "")

    raw = base64.b64decode(b64)
    print(f"Decoded size: {len(raw)} bytes")
    print(f"First 64 bytes (hex): {raw[:64].hex()}")
    print(f"First 64 bytes (raw): {raw[:64]}")
    print()

    # Check magic bytes
    print("=== Format Detection ===")

    # 1. Zlib (starts with 0x78 0x9C or 0x78 0x01 or 0x78 0xDA)
    if raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA):
        print("[+] Looks like ZLIB compressed data")
        try:
            decompressed = zlib.decompress(raw)
            print(f"    Decompressed size: {len(decompressed)} bytes")
            print(f"    First 200 chars: {decompressed[:200]}")
            with open("decoded_zlib.bin", "wb") as f:
                f.write(decompressed)
            print("    Saved to decoded_zlib.bin")
        except Exception as e:
            print(f"    Decompression failed: {e}")
        print()

    # 2. Gzip (starts with 0x1F 0x8B)
    if raw[0] == 0x1F and raw[1] == 0x8B:
        print("[+] Looks like GZIP compressed data")
        try:
            decompressed = gzip.decompress(raw)
            print(f"    Decompressed size: {len(decompressed)} bytes")
            print(f"    First 200 chars: {decompressed[:200]}")
            with open("decoded_gzip.bin", "wb") as f:
                f.write(decompressed)
            print("    Saved to decoded_gzip.bin")
        except Exception as e:
            print(f"    Decompression failed: {e}")
        print()

    # 3. .NET BinaryFormatter (starts with 0x00 0x01 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF)
    bf_magic = b'\x00\x01\x00\x00\x00\xff\xff\xff\xff'
    if raw[:9] == bf_magic:
        print("[+] Looks like .NET BinaryFormatter")
        print("    WARNING: BinaryFormatter is a known deserialization RCE vector!")
        with open("decoded_bf.bin", "wb") as f:
            f.write(raw)
        print("    Saved raw to decoded_bf.bin")
        print()

    # 4. WCF Binary XML (starts with various record type bytes)
    # Binary XML records start with record type IDs
    # Common first bytes: 0x40 (ShortElement), 0x56 (PrefixElement), etc.
    # The .NET binary XML format uses specific record type identifiers
    wcf_binary_indicators = {
        0x40: "ShortElement",
        0x41: "Element", 
        0x42: "ShortDictionaryElement",
        0x43: "DictionaryElement",
        0x44: "PrefixDictionaryElement_a",
        0x56: "PrefixElement_a-z",
        0x01: "EndElement",
        0x02: "Comment",
        0x04: "Array",
        0x06: "ShortDictionaryAttribute",
        0x07: "DictionaryAttribute",
    }
    if raw[0] in wcf_binary_indicators:
        print(f"[+] Could be WCF Binary XML (first byte 0x{raw[0]:02x} = {wcf_binary_indicators.get(raw[0], 'unknown')})")
        with open("decoded_wcf.bin", "wb") as f:
            f.write(raw)
        print("    Saved raw to decoded_wcf.bin")
        # Look for readable strings in the binary
        print("    Searching for readable strings...")
        strings = extract_strings(raw)
        for s in strings[:30]:
            print(f"      '{s}'")
        print()

    # 5. Raw XML (starts with < or BOM)
    if raw[0] in (0x3C, 0xEF, 0xFE, 0xFF):  # '<', BOM variants
        print("[+] Looks like raw XML/text")
        print(f"    Content: {raw[:500].decode('utf-8', errors='replace')}")
        print()

    # 6. NetDataContractSerializer (similar to DataContractSerializer but with type hints)
    # Often starts with XML-like content with __type attributes

    # General: dump strings found in the binary
    print("=== All readable strings in blob ===")
    strings = extract_strings(raw, min_len=4)
    for s in strings[:50]:
        print(f"  '{s}'")

    # Save raw bytes for manual inspection
    with open("decoded_raw.bin", "wb") as f:
        f.write(raw)
    print(f"\nRaw bytes saved to decoded_raw.bin")
    print(f"Inspect with: xxd decoded_raw.bin | head -50")


def extract_strings(data: bytes, min_len: int = 3) -> list:
    """Extract readable ASCII strings from binary data."""
    strings = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


if __name__ == "__main__":
    main()
