#!/usr/bin/env python3
"""
parser_lfh.py - ZIP/APK Local File Header parser
Thesis: Detection of Malicious APK Files through ZIP Header Analysis

Author: Hosam
Created: 2026-05-09
Last updated: 2026-05-13
Version: 2.0 - added anomaly detection with exact offset
"""

import struct
import sys
import os

# --- Constants --------------------------------------------------------------

LFH_SIGNATURE  = b'\x50\x4b\x03\x04'  # prefix b for bytes 50 4B 03 04
DEX_SIGNATURE  = b'\x64\x65\x78\x0a'  # 64 65 78 0A
LFH_FIXED_SIZE = 30  # Local File Header always occupies 30 fixed bytes

COMPRESSION_METHODS = {  # maps each number to the method name
    0:  "Stored (no compression)",
    8:  "Deflate",
    9:  "Deflate64",
    12: "BZIP2",
    14: "LZMA",
}

# Anomaly severity levels
CRITICAL = "CRITICAL"
WARNING  = "WARNING"
INFO     = "INFO"

# --- Anomaly class ----------------------------------------------------------

class Anomaly:
    def __init__(self, severity, field, offset, value, description):
        self.severity    = severity
        self.field       = field
        self.offset      = offset
        self.value       = value
        self.description = description

    def __str__(self):
        return (f"[{self.severity}] offset {self.offset} | "
                f"field: {self.field} | "
                f"value: {self.value} | "
                f"{self.description}")

# --- Main function ----------------------------------------------------------

def parse_local_file_header(filepath):
    """
    Reads and analyzes the first Local File Header of a ZIP/APK file.
    Detects anomalies with the exact offset for each field.

    Input:
        filepath (str): path to the ZIP or APK file

    Output:
        tuple (dict, list[Anomaly]) or (None, list[Anomaly])
    """

    anomalies = []  # empty at the start - we append Anomaly objects as we find them

    if not os.path.exists(filepath):
        return None, anomalies

    filesize = os.path.getsize(filepath)

    with open(filepath, 'rb') as f:

        # -- CHECK 1: Magic bytes at offset 0x00 ---------------------------
        magic = f.read(4)

        if magic == DEX_SIGNATURE:
            anomalies.append(Anomaly(
                CRITICAL,
                "signature",
                "0x00",
                magic.hex(' ').upper(),
                "DEX magic bytes -- possible Janus APK! Expected: 50 4B 03 04"
            ))
            return None, anomalies

        if magic != LFH_SIGNATURE:
            anomalies.append(Anomaly(
                CRITICAL,
                "signature",
                "0x00",
                magic.hex(' ').upper(),
                "Invalid magic bytes. Expected: 50 4B 03 04"
            ))
            return None, anomalies

        # -- STEP 2: Read the 30 fixed bytes -------------------------------
        f.seek(0)
        raw = f.read(LFH_FIXED_SIZE)

        if len(raw) < LFH_FIXED_SIZE:
            anomalies.append(Anomaly(
                CRITICAL, "header", "0x00",
                f"{len(raw)} bytes",
                f"File too small. Minimum {LFH_FIXED_SIZE} bytes"))
            return None, anomalies

        # -- STEP 3: Unpack ------------------------------------------------
        fields = struct.unpack('<4sHHHHHIIIHH', raw)  # '<' little-endian, '4s' 4-byte string
                                                       # 'H' unsigned short (2 bytes), 'I' unsigned int (4 bytes)

        signature       = fields[0]   # offset 0x00
        version_needed  = fields[1]   # offset 0x04
        flags           = fields[2]   # offset 0x06
        compression     = fields[3]   # offset 0x08
        mod_time        = fields[4]   # offset 0x0A
        mod_date        = fields[5]   # offset 0x0C
        crc32           = fields[6]   # offset 0x0E
        compressed_size = fields[7]   # offset 0x12
        uncompr_size    = fields[8]   # offset 0x16
        filename_length = fields[9]   # offset 0x1A
        extra_length    = fields[10]  # offset 0x1C

        # -- STEP 4: Read filename -----------------------------------------
        filename_raw = f.read(filename_length)
        try:
            filename = filename_raw.decode('utf-8')
        except UnicodeDecodeError:
            filename = filename_raw.decode('latin-1')
            anomalies.append(Anomaly(
                INFO, "filename", "0x1E",
                repr(filename_raw),
                "Filename not UTF-8 -- decoded with latin-1"))

        # -- STEP 5: Flag analysis -----------------------------------------
        flag_encrypted = bool(flags & 0x0001)
        flag_data_desc = bool(flags & 0x0008)

        # -- STEP 6: Anomaly detection with exact offset -------------------

        # version_needed
        if version_needed == 0:
            anomalies.append(Anomaly(
                WARNING, "version_needed", "0x04",
                hex(version_needed),
                "version_needed = 0 -- non-standard value"))
        elif version_needed > 63:
            anomalies.append(Anomaly(
                WARNING, "version_needed", "0x04",
                hex(version_needed),
                f"version_needed = {version_needed} -- unusual value (expected <= 63)"))

        # compression method
        if compression not in COMPRESSION_METHODS:
            anomalies.append(Anomaly(
                WARNING, "compression_method", "0x08",
                hex(compression),
                f"Unknown compression method: {compression}"))

        # encrypted file
        if flag_encrypted:
            anomalies.append(Anomaly(
                WARNING, "general_purpose_flag", "0x06",
                hex(flags),
                "Bit 0 set -- encrypted file"))

        # Data Descriptor (INFO)
        if flag_data_desc:
            anomalies.append(Anomaly(
                INFO, "general_purpose_flag", "0x06",
                hex(flags),
                "Bit 3 set -- CRC/sizes in Data Descriptor (normal)"))

        # CRC32 zero without bit 3
        if crc32 == 0 and not flag_data_desc:
            anomalies.append(Anomaly(
                WARNING, "crc32", "0x0E",
                "0x00000000",
                "CRC32 = 0 without Data Descriptor -- anomaly"))

        # sizes zero without bit 3
        if compressed_size == 0 and uncompr_size == 0 and not flag_data_desc:
            anomalies.append(Anomaly(
                WARNING, "compressed_size / uncompressed_size", "0x12 / 0x16",
                "0 / 0",
                "Sizes = 0 without Data Descriptor -- anomaly"))

        # empty filename
        if filename_length == 0:
            anomalies.append(Anomaly(
                WARNING, "filename_length", "0x1A",
                "0",
                "Empty filename -- anomaly"))

        # filename with path traversal
        if '..' in filename or filename.startswith('/'):
            anomalies.append(Anomaly(
                CRITICAL, "filename", "0x1E",
                filename,
                "Path traversal detected in filename -- possible attack"))

        # compressed > uncompressed (impossible with compression)
        if (compressed_size > 0 and uncompr_size > 0 and
                compressed_size > uncompr_size and compression != 0):
            anomalies.append(Anomaly(
                WARNING, "compressed_size", "0x12",
                f"{compressed_size} > {uncompr_size}",
                "compressed_size > uncompressed_size with Deflate -- anomaly"))

        if compressed_size > filesize:
            anomalies.append(Anomaly(
                 WARNING, "compressed_size", "0x12",
                 f"{compressed_size} bytes",
                 f"compressed_size ({compressed_size}) > file size ({filesize}) -- impossible"))


        # -- STEP 7: Build result ------------------------------------------
        result = {
            'signature'       : signature,
            'version_needed'  : version_needed,
            'flags'           : flags,
            'compression'     : compression,
            'mod_time'        : mod_time,
            'mod_date'        : mod_date,
            'crc32'           : crc32,
            'compressed_size' : compressed_size,
            'uncompr_size'    : uncompr_size,
            'filename_length' : filename_length,
            'extra_length'    : extra_length,
            'filename'        : filename,
            'flag_encrypted'  : flag_encrypted,
            'flag_data_desc'  : flag_data_desc,
            'filesize'        : filesize,
        }

        return result, anomalies


# --- Print function ---------------------------------------------------------

def print_lfh(result, anomalies, filepath):

    compression_name = COMPRESSION_METHODS.get(
        result['compression'], f"Unknown ({result['compression']})")
    version = result['version_needed']
    version_str = f"{version // 10}.{version % 10}"

    print("=" * 65)
    print(f"  LOCAL FILE HEADER ANALYSIS -- v2.0")
    print(f"  File: {filepath}")
    print(f"  Size: {result['filesize']} bytes")
    print("=" * 65)

    print(f"\n{'FIELD':<25} {'OFFSET':<8} {'HEX':<15} {'VALUE'}")
    print("-" * 65)

    print(f"{'signature':<25} {'0x00':<8} "
          f"{result['signature'].hex(' ').upper():<15} ZIP valid ")

    print(f"{'version_needed':<25} {'0x04':<8} "
          f"{result['version_needed']:04x}{'':>11} ZIP v{version_str}")

    print(f"{'general_purpose_flag':<25} {'0x06':<8} "
          f"{result['flags']:04x}{'':>11} "
          f"{'ENCRYPTED ' if result['flag_encrypted'] else 'not encrypted'} | "
          f"DataDesc: {'YES ' if result['flag_data_desc'] else 'NO'}")

    print(f"{'compression_method':<25} {'0x08':<8} "
          f"{result['compression']:04x}{'':>11} {compression_name}")

    print(f"{'last_mod_time':<25} {'0x0A':<8} "
          f"{result['mod_time']:04x}{'':>11} (MS-DOS)")

    print(f"{'last_mod_date':<25} {'0x0C':<8} "
          f"{result['mod_date']:04x}{'':>11} (MS-DOS)")

    if result['flag_data_desc']:
        print(f"{'crc32':<25} {'0x0E':<8} {'00000000':<15} in Data Descriptor")
        print(f"{'compressed_size':<25} {'0x12':<8} {'00000000':<15} in Data Descriptor")
        print(f"{'uncompressed_size':<25} {'0x16':<8} {'00000000':<15} in Data Descriptor")
    else:
        print(f"{'crc32':<25} {'0x0E':<8} "
              f"{result['crc32']:08x}{'':>7} 0x{result['crc32']:08x}")
        print(f"{'compressed_size':<25} {'0x12':<8} "
              f"{result['compressed_size']:08x}{'':>7} {result['compressed_size']} bytes")
        print(f"{'uncompressed_size':<25} {'0x16':<8} "
              f"{result['uncompr_size']:08x}{'':>7} {result['uncompr_size']} bytes")

    print(f"{'filename_length':<25} {'0x1A':<8} "
          f"{result['filename_length']:04x}{'':>11} {result['filename_length']} bytes")
    print(f"{'extra_field_length':<25} {'0x1C':<8} "
          f"{result['extra_length']:04x}{'':>11} {result['extra_length']} bytes")
    print(f"{'filename':<25} {'0x1E':<8} {'':>15} \"{result['filename']}\"")

    # -- Anomalies section ---------------------------------------------------
    print("\n" + "=" * 65)
    print("  ANOMALIES DETECTED")
    print("=" * 65)

    criticals = [a for a in anomalies if a.severity == CRITICAL]
    warnings  = [a for a in anomalies if a.severity == WARNING]
    infos     = [a for a in anomalies if a.severity == INFO]

    if not anomalies:
        print("  No anomalies ")
    else:
        for a in criticals:
            print(f"   [CRITICAL] offset {a.offset} -- {a.field}: {a.description}")
        for a in warnings:
            print(f"   [WARNING]  offset {a.offset} -- {a.field}: {a.description}")
        for a in infos:
            print(f"   [INFO]     offset {a.offset} -- {a.field}: {a.description}")

    print("=" * 65)
    print(f"  Total: {len(criticals)} CRITICAL | {len(warnings)} WARNING | {len(infos)} INFO")
    print("=" * 65)

# --- Core function -- detect_header_anomaly() -------------------------------

def detect_header_anomaly(filepath):
    """
    Core function of the structural header validator.
    Analyzes a ZIP/APK file and returns the list of anomalies found.

    Input:
        filepath (str): path to the ZIP or APK file

    Output:
        list[dict] -- list of anomalies, each with:
            - severity    : "CRITICAL" | "WARNING" | "INFO"
            - field       : name of the anomalous field
            - offset      : exact offset in the file (hex string)
            - value       : value found
            - description : natural-language explanation

    Example output:
        [
            {
                "severity": "CRITICAL",
                "field": "signature",
                "offset": "0x00",
                "value": "64 65 78 0A",
                "description": "DEX magic bytes -- possible Janus APK!"
            }
        ]
    """

    _, anomalies = parse_local_file_header(filepath)

    # Convert list of Anomaly objects into list of dictionaries
    result = []
    for a in anomalies:
        result.append({
            "severity"    : a.severity,
            "field"       : a.field,
            "offset"      : a.offset,
            "value"       : a.value,
            "description" : a.description
        })

    return result


def is_janus(filepath):
    """
    Quick check whether a file is a possible Janus APK.

    Input:
        filepath (str): path to the APK file

    Output:
        bool -- True if DEX magic bytes found at offset 0x00
    """

    anomalies = detect_header_anomaly(filepath)
    return any(
        a["field"] == "signature" and "Janus" in a["description"]
        for a in anomalies
    )


def get_anomalies_by_severity(filepath, severity):
    """
    Returns only the anomalies of a given severity.

    Input:
        filepath (str): path to the file
        severity (str): "CRITICAL" | "WARNING" | "INFO"

    Output:
        list[dict] -- anomalies filtered by severity
    """

    anomalies = detect_header_anomaly(filepath)
    return [a for a in anomalies if a["severity"] == severity]

# --- Entry point ------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/parser_lfh.py <file.zip|file.apk>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"\n[*] Analysis of: {filepath}\n")

    result, anomalies = parse_local_file_header(filepath)

    if result:
        print_lfh(result, anomalies, filepath)
    else:
        print("=" * 65)
        print("  ANALYSIS FAILED -- CRITICAL ANOMALIES")
        print("=" * 65)
        for a in anomalies:
            print(f"    [CRITICAL] offset {a.offset} -- {a.field}: {a.description}")
        print("=" * 65)


if __name__ == "__main__":
    main()
