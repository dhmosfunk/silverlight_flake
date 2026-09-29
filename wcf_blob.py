#!/usr/bin/env python3
"""
Decode a WCF zlib+binary-XML blob, inspect it, modify values, re-encode.

The format is: base64 -> zlib decompress -> .NET Binary XML

For simple value modifications (changing numbers, short strings), we can
do binary search-and-replace on the decompressed data and re-encode.

Usage:
    python3 wcf_blob_tool.py decode blob.txt          # Decode and inspect
    python3 wcf_blob_tool.py strings blob.txt          # Extract readable strings
    python3 wcf_blob_tool.py modify blob.txt           # Interactive modify and re-encode
    python3 wcf_blob_tool.py hexdump blob.txt          # Full hex dump
"""

import sys
import base64
import zlib
import struct
import re


def load_blob(filepath: str) -> bytes:
    """Load base64 file, decode, decompress."""
    with open(filepath, "r") as f:
        b64 = f.read().strip().replace("\n", "").replace("\r", "").replace(" ", "")
    raw = base64.b64decode(b64)
    if raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA):
        return zlib.decompress(raw)
    return raw


def encode_blob(data: bytes) -> str:
    """Compress and base64 encode."""
    compressed = zlib.compress(data)
    return base64.b64encode(compressed).decode('ascii')


def extract_strings(data: bytes, min_len: int = 3) -> list:
    """Extract readable ASCII/UTF-8 strings with their offsets."""
    results = []
    current = []
    start_offset = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if not current:
                start_offset = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start_offset, "".join(current)))
            current = []
    if len(current) >= min_len:
        results.append((start_offset, "".join(current)))
    return results


def hexdump(data: bytes, start: int = 0, length: int = None):
    """Pretty hex dump."""
    if length:
        data = data[start:start+length]
    else:
        data = data[start:]
    
    for i in range(0, len(data), 16):
        hex_part = " ".join(f"{b:02x}" for b in data[i:i+16])
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[i:i+16])
        print(f"  {start+i:04x}: {hex_part:<48s} {ascii_part}")


def find_and_replace_int32(data: bytes, old_val: int, new_val: int) -> bytes:
    """Find a 32-bit little-endian integer and replace it."""
    old_bytes = struct.pack("<i", old_val)
    new_bytes = struct.pack("<i", new_val)
    count = data.count(old_bytes)
    if count == 0:
        print(f"  Integer {old_val} not found as int32 LE")
        # Try big-endian
        old_bytes_be = struct.pack(">i", old_val)
        count_be = data.count(old_bytes_be)
        if count_be > 0:
            print(f"  Found {count_be} occurrence(s) as int32 BE")
            return data.replace(old_bytes_be, struct.pack(">i", new_val), 1)
        # Try as string
        old_str = str(old_val).encode('utf-8')
        count_str = data.count(old_str)
        if count_str > 0:
            print(f"  Found {count_str} occurrence(s) as UTF-8 string '{old_val}'")
            new_str = str(new_val).encode('utf-8')
            if len(old_str) == len(new_str):
                return data.replace(old_str, new_str, 1)
            else:
                print(f"  WARNING: String lengths differ ({len(old_str)} vs {len(new_str)})")
                print(f"  This may corrupt the binary structure if lengths change!")
                return data.replace(old_str, new_str, 1)
        return data
    print(f"  Found {count} occurrence(s) as int32 LE")
    return data.replace(old_bytes, new_bytes, 1)


def find_and_replace_string(data: bytes, old_str: str, new_str: str) -> bytes:
    """Find and replace a UTF-8 string in the binary data."""
    old_bytes = old_str.encode('utf-8')
    new_bytes = new_str.encode('utf-8')
    count = data.count(old_bytes)
    if count == 0:
        print(f"  String '{old_str}' not found")
        return data
    print(f"  Found {count} occurrence(s) of '{old_str}'")
    
    if len(old_bytes) != len(new_bytes):
        print(f"  WARNING: Lengths differ ({len(old_bytes)} -> {len(new_bytes)})")
        print(f"  Binary XML has length-prefixed strings - this WILL break unless")
        print(f"  you also update the length prefix byte before the string.")
        print(f"  For safety, use same-length replacements or update length bytes.")
        
        # Try to find length-prefixed version and update both
        # .NET Binary XML prefixes strings with their byte length as a variable-length int
        old_len_prefix = encode_multibyte_int(len(old_bytes))
        new_len_prefix = encode_multibyte_int(len(new_bytes))
        prefixed_old = old_len_prefix + old_bytes
        prefixed_new = new_len_prefix + new_bytes
        
        pcount = data.count(prefixed_old)
        if pcount > 0:
            print(f"  Found {pcount} length-prefixed occurrence(s) - safe to replace!")
            return data.replace(prefixed_old, prefixed_new, 1)
        else:
            print(f"  Could not find length-prefixed version. Replacing raw (risky).")
            resp = input("  Proceed with raw replacement? (y/n): ").strip().lower()
            if resp == 'y':
                return data.replace(old_bytes, new_bytes, 1)
            return data
    
    return data.replace(old_bytes, new_bytes, 1)


def encode_multibyte_int(value: int) -> bytes:
    """Encode an integer as .NET multi-byte int31 format."""
    result = []
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def cmd_decode(filepath):
    data = load_blob(filepath)
    print(f"Decompressed size: {len(data)} bytes")
    print(f"\nFirst 128 bytes hex dump:")
    hexdump(data, 0, 128)
    print(f"\nLast 64 bytes hex dump:")
    hexdump(data, max(0, len(data)-64))
    
    # Save decompressed
    outpath = filepath.rsplit(".", 1)[0] + "_decoded.bin"
    with open(outpath, "wb") as f:
        f.write(data)
    print(f"\nDecompressed data saved to: {outpath}")
    
    print(f"\nReadable strings:")
    for offset, s in extract_strings(data, min_len=4):
        print(f"  0x{offset:04x}: '{s}'")


def cmd_strings(filepath):
    data = load_blob(filepath)
    for offset, s in extract_strings(data, min_len=3):
        print(f"  0x{offset:04x}: '{s}'")


def cmd_hexdump(filepath):
    data = load_blob(filepath)
    hexdump(data)


def cmd_modify(filepath):
    data = load_blob(filepath)
    print(f"Decompressed size: {len(data)} bytes")
    print(f"\nReadable strings:")
    for offset, s in extract_strings(data, min_len=3):
        print(f"  0x{offset:04x}: '{s}'")
    
    print(f"\n--- Modification mode ---")
    print("Commands:")
    print("  int <old> <new>     - Replace int32 value")
    print("  str <old> <new>     - Replace string value")
    print("  byte <offset> <hex> - Replace bytes at offset")
    print("  dump <offset> <len> - Hex dump at offset")
    print("  save                - Compress and save")
    print("  quit                - Exit")
    
    modified = data
    while True:
        try:
            cmd = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        if not cmd:
            continue
        
        parts = cmd.split(None, 2)
        
        if parts[0] == "quit":
            break
        elif parts[0] == "save":
            encoded = encode_blob(modified)
            outpath = filepath.rsplit(".", 1)[0] + "_modified.b64"
            with open(outpath, "w") as f:
                f.write(encoded)
            print(f"Saved to: {outpath}")
            print(f"Base64 length: {len(encoded)}")
        elif parts[0] == "int" and len(parts) == 3:
            old_val = int(parts[1])
            new_val = int(parts[2])
            modified = find_and_replace_int32(modified, old_val, new_val)
        elif parts[0] == "str" and len(parts) == 3:
            modified = find_and_replace_string(modified, parts[1], parts[2])
        elif parts[0] == "byte" and len(parts) == 3:
            offset = int(parts[1], 0)
            new_bytes = bytes.fromhex(parts[2])
            modified = modified[:offset] + new_bytes + modified[offset+len(new_bytes):]
            print(f"  Replaced {len(new_bytes)} bytes at 0x{offset:04x}")
        elif parts[0] == "dump" and len(parts) >= 2:
            offset = int(parts[1], 0)
            length = int(parts[2]) if len(parts) == 3 else 64
            hexdump(modified, offset, length)
        else:
            print("Unknown command")


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 wcf_blob_tool.py decode  blob.txt   # Decode and inspect")
        print("  python3 wcf_blob_tool.py strings blob.txt   # Extract strings")
        print("  python3 wcf_blob_tool.py hexdump blob.txt   # Full hex dump")
        print("  python3 wcf_blob_tool.py modify  blob.txt   # Interactive modify")
        sys.exit(1)

    cmd = sys.argv[1]
    filepath = sys.argv[2]

    if cmd == "decode":
        cmd_decode(filepath)
    elif cmd == "strings":
        cmd_strings(filepath)
    elif cmd == "hexdump":
        cmd_hexdump(filepath)
    elif cmd == "modify":
        cmd_modify(filepath)
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
