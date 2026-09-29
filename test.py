#!/usr/bin/env python3
"""
Converts a QuerySpec XML payload into the zlib-compressed base64 format
expected by the LoadData SOAP endpoint.

Usage:
    python3 queryspec_encoder.py input.xml
    python3 queryspec_encoder.py input.xml --decode  (to decode an existing base64 blob)
"""

import sys
import zlib
import base64

def encode_queryspec(xml_bytes: bytes) -> str:
    """XML bytes -> zlib compress -> base64 encode"""
    compressed = zlib.compress(xml_bytes)
    encoded = base64.b64encode(compressed).decode('ascii')
    return encoded

def decode_queryspec(b64_string: str) -> bytes:
    """base64 decode -> zlib decompress -> XML bytes"""
    compressed = base64.b64decode(b64_string)
    decompressed = zlib.decompress(compressed)
    return decompressed

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Encode XML to base64:  python3 queryspec_encoder.py input.xml")
        print("  Decode base64 to XML:  python3 queryspec_encoder.py encoded.txt --decode")
        sys.exit(1)

    filepath = sys.argv[1]
    decode_mode = "--decode" in sys.argv

    with open(filepath, "rb") as f:
        data = f.read()

    if decode_mode:
        # Decode: base64 string -> XML
        b64_string = data.decode('utf-8').strip()
        xml_bytes = decode_queryspec(b64_string)
        print("=== Decoded XML ===")
        print(xml_bytes.decode('utf-8'))
        
        # Also save to file
        outpath = filepath + ".decoded.xml"
        with open(outpath, "wb") as f:
            f.write(xml_bytes)
        print(f"\nSaved to: {outpath}")
    else:
        # Encode: XML -> base64 string
        encoded = encode_queryspec(data)
        print("=== Encoded base64 ===")
        print(encoded)
        
        # Also save to file
        outpath = filepath + ".b64"
        with open(outpath, "w") as f:
            f.write(encoded)
        print(f"\nSaved to: {outpath}")

if __name__ == "__main__":
    main()
