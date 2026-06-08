#!/usr/bin/env python3
"""
parser_lfh.py — Parser del Local File Header ZIP/APK
Direzione 1 della tesi: Detection of Malicious APK Files through ZIP Header Analysis

Autore: Husam
Data creazione: 2026-05-09
Ultimo aggiornamento: 2026-05-13
Versione: 2.0 — aggiunto rilevamento anomalie con offset esatto
"""

import struct
import sys
import os

# ─── Costanti ────────────────────────────────────────────────────────────────

LFH_SIGNATURE  = b'\x50\x4b\x03\x04'  #prefissio b per byte 50 4B 03 04
DEX_SIGNATURE  = b'\x64\x65\x78\x0a'  # 64 65 78 0A
LFH_FIXED_SIZE = 30 # Local File Header occupa 30 byte  fissi sempre

COMPRESSION_METHODS = { # mappa ogni numero al nome del metodo
    0:  "Stored (nessuna compressione)",
    8:  "Deflate",
    9:  "Deflate64",
    12: "BZIP2",
    14: "LZMA",
}

# I livelli di severita anomalie
CRITICAL = "CRITICAL"
WARNING  = "WARNING"
INFO     = "INFO"

# ─── Classe Anomalia ─────────────────────────────────────────────────────────

class Anomalia: 
    def __init__(self, severita, campo, offset, valore, descrizione): # Constructor ( in java like this.name = name)
        self.severita   = severita
        self.campo      = campo
        self.offset     = offset
        self.valore     = valore
        self.descrizione = descrizione

    def __str__(self): # in java public String toString() { return ...}
        return (f"[{self.severita}] offset {self.offset} | "
                f"campo: {self.campo} | "
                f"valore: {self.valore} | "
                f"{self.descrizione}")

# ─── Funzione principale ──────────────────────────────────────────────────────

def parse_local_file_header(filepath):
    """
    Legge e analizza il primo Local File Header di un file ZIP/APK.
    Rileva anomalie con offset esatto per ogni campo.

    Input:
        filepath (str): percorso al file ZIP o APK

    Output:
        tuple (dict, list[Anomalia]) oppure (None, list[Anomalia])
    """

    anomalie = [] # Lista vuota all'inizio — ci aggiungeremo oggetti Anomalia man mano che li troviamo. 

    if not os.path.exists(filepath): # controllo esistenza file
        return None, anomalie

    filesize = os.path.getsize(filepath) # legge dimensione del file in byte senza aprirlo

    with open(filepath, 'rb') as f: # rb = read binary, with garantisce che il file viene chiusto automaticamente se si verifica un errore dentro il blocco

        # ── VERIFICA 1: Magic bytes a offset 0x00 ─────────────────────────
        magic = f.read(4) # legge primi 4 byte del file

        if magic == DEX_SIGNATURE:
            anomalie.append(Anomalia(
                CRITICAL,
                "signature",
                "0x00",
                magic.hex(' ').upper(), # converte i byte in stringa hex con spazi
                "DEX magic bytes — possibile APK Janus! Atteso: 50 4B 03 04"
            ))
            return None, anomalie

        if magic != LFH_SIGNATURE: #  se non è DEX ma non è nemmeno ZIP, è qualcosa di sconosciuto. CRITICAL
            anomalie.append(Anomalia(
                CRITICAL,
                "signature",
                "0x00",
                magic.hex(' ').upper(),
                f"Magic bytes non validi. Atteso: 50 4B 03 04"
            ))
            return None, anomalie

        # ── STEP 2: Leggi i 30 byte fissi ─────────────────────────────────
        f.seek(0) # riporta il cursore all'inizio del file.
        raw = f.read(LFH_FIXED_SIZE) # legge esattamente 30 byte e li mette in raw come sequenza di byte grezza.

        if len(raw) < LFH_FIXED_SIZE: # Verifica che abbiamo letto tutti e 30 i byte. Un file più corto di 30 byte non può contenere un LFH valido.
            anomalie.append(Anomalia(
                CRITICAL, "header", "0x00",
                f"{len(raw)} byte",
                f"File troppo piccolo. Minimo {LFH_FIXED_SIZE} byte"))
            return None, anomalie

        # ── STEP 3: Unpack ────────────────────────────────────────────────
        fields = struct.unpack('<4sHHHHHIIIHH', raw) # '<' - little-endian, '4s' leggi 4 byte come stringa di byte
                                                     # 'H'-  unsigned short, 2 byte, 'I'- unsigned int, 4 byte

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

        # ── STEP 4: Leggi filename ────────────────────────────────────────
        filename_raw = f.read(filename_length)
        try:
            filename = filename_raw.decode('utf-8')
        except UnicodeDecodeError:
            filename = filename_raw.decode('latin-1')
            anomalie.append(Anomalia(
                INFO, "filename", "0x1E",
                repr(filename_raw),
                "Filename non UTF-8 — decodificato con latin-1"))

        # ── STEP 5: Analisi flag ──────────────────────────────────────────
        flag_encrypted = bool(flags & 0x0001)
        flag_data_desc = bool(flags & 0x0008)

        # ── STEP 6: Rilevamento anomalie con offset esatto ────────────────

        # version_needed
        if version_needed == 0: # valore non standard
            anomalie.append(Anomalia(
                WARNING, "version_needed", "0x04",
                hex(version_needed),
                "version_needed = 0 — valore non standard"))
        elif version_needed > 63: # valore insolito
            anomalie.append(Anomalia(
                WARNING, "version_needed", "0x04",
                hex(version_needed),
                f"version_needed = {version_needed} — valore insolito (atteso <= 63)"))

        # compression method
        if compression not in COMPRESSION_METHODS: # metodo sconosciuto
            anomalie.append(Anomalia(
                WARNING, "compression_method", "0x08",
                hex(compression),
                f"Metodo di compressione sconosciuto: {compression}"))

        # file cifrato
        if flag_encrypted: 
            anomalie.append(Anomalia(
                WARNING, "general_purpose_flag", "0x06",
                hex(flags),
                "Bit 0 attivo — file cifrato"))

        # Data Descriptor (INFO)
        if flag_data_desc:
            anomalie.append(Anomalia(
                INFO, "general_purpose_flag", "0x06",
                hex(flags),
                "Bit 3 attivo — CRC/sizes nel Data Descriptor (normale)"))

        # CRC32 zero senza bit 3
        if crc32 == 0 and not flag_data_desc:
            anomalie.append(Anomalia(
                WARNING, "crc32", "0x0E",
                "0x00000000",
                "CRC32 = 0 senza Data Descriptor — anomalia"))

        # sizes zero senza bit 3
        if compressed_size == 0 and uncompr_size == 0 and not flag_data_desc:
            anomalie.append(Anomalia(
                WARNING, "compressed_size / uncompressed_size", "0x12 / 0x16",
                "0 / 0",
                "Sizes = 0 senza Data Descriptor — anomalia"))

        # filename vuoto
        if filename_length == 0:
            anomalie.append(Anomalia(
                WARNING, "filename_length", "0x1A",
                "0",
                "Filename vuoto — anomalia"))

        # filename con path traversal
        if '..' in filename or filename.startswith('/'):
            anomalie.append(Anomalia(
                CRITICAL, "filename", "0x1E",
                filename,
                "Path traversal rilevato nel filename — possibile attacco"))

        # compressed > uncompressed (impossibile con compressione)
        if (compressed_size > 0 and uncompr_size > 0 and
                compressed_size > uncompr_size and compression != 0):
            anomalie.append(Anomalia(
                WARNING, "compressed_size", "0x12",
                f"{compressed_size} > {uncompr_size}",
                "compressed_size > uncompressed_size con Deflate — anomalia"))
        
        if compressed_size > filesize:
            anomalie.append(Anomalia(
                 WARNING, "compressed_size", "0x12",
                 f"{compressed_size} byte",
                 f"compressed_size ({compressed_size}) > dimensione file ({filesize}) — impossibile"))
    

        # ── STEP 7: Costruisci risultato ──────────────────────────────────
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

        return result, anomalie


# ─── Funzione di stampa ───────────────────────────────────────────────────────

def print_lfh(result, anomalie, filepath):

    compression_name = COMPRESSION_METHODS.get(
        result['compression'], f"Sconosciuto ({result['compression']})")
    version = result['version_needed']
    version_str = f"{version // 10}.{version % 10}"

    print("=" * 65)
    print(f"  ANALISI LOCAL FILE HEADER — v2.0")
    print(f"  File: {filepath}")
    print(f"  Dimensione: {result['filesize']} byte")
    print("=" * 65)

    print(f"\n{'CAMPO':<25} {'OFFSET':<8} {'HEX':<15} {'VALORE'}")
    print("-" * 65)

    print(f"{'signature':<25} {'0x00':<8} "
          f"{result['signature'].hex(' ').upper():<15} ZIP valido ")

    print(f"{'version_needed':<25} {'0x04':<8} "
          f"{result['version_needed']:04x}{'':>11} ZIP v{version_str}")

    print(f"{'general_purpose_flag':<25} {'0x06':<8} "
          f"{result['flags']:04x}{'':>11} "
          f"{'CIFRATO ' if result['flag_encrypted'] else 'non cifrato'} | "
          f"DataDesc: {'SI ' if result['flag_data_desc'] else 'NO'}")

    print(f"{'compression_method':<25} {'0x08':<8} "
          f"{result['compression']:04x}{'':>11} {compression_name}")

    print(f"{'last_mod_time':<25} {'0x0A':<8} "
          f"{result['mod_time']:04x}{'':>11} (MS-DOS)")

    print(f"{'last_mod_date':<25} {'0x0C':<8} "
          f"{result['mod_date']:04x}{'':>11} (MS-DOS)")

    if result['flag_data_desc']:
        print(f"{'crc32':<25} {'0x0E':<8} {'00000000':<15} nel Data Descriptor")
        print(f"{'compressed_size':<25} {'0x12':<8} {'00000000':<15} nel Data Descriptor")
        print(f"{'uncompressed_size':<25} {'0x16':<8} {'00000000':<15} nel Data Descriptor")
    else:
        print(f"{'crc32':<25} {'0x0E':<8} "
              f"{result['crc32']:08x}{'':>7} 0x{result['crc32']:08x}")
        print(f"{'compressed_size':<25} {'0x12':<8} "
              f"{result['compressed_size']:08x}{'':>7} {result['compressed_size']} byte")
        print(f"{'uncompressed_size':<25} {'0x16':<8} "
              f"{result['uncompr_size']:08x}{'':>7} {result['uncompr_size']} byte")

    print(f"{'filename_length':<25} {'0x1A':<8} "
          f"{result['filename_length']:04x}{'':>11} {result['filename_length']} byte")
    print(f"{'extra_field_length':<25} {'0x1C':<8} "
          f"{result['extra_length']:04x}{'':>11} {result['extra_length']} byte")
    print(f"{'filename':<25} {'0x1E':<8} {'':>15} \"{result['filename']}\"")

    # ── Sezione anomalie ──────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  ANOMALIE RILEVATE")
    print("=" * 65)

    critiche  = [a for a in anomalie if a.severita == CRITICAL]
    warnings  = [a for a in anomalie if a.severita == WARNING]
    infos     = [a for a in anomalie if a.severita == INFO]

    if not anomalie:
        print("  Nessuna anomalia ")
    else:
        for a in critiche:
            print(f"   [CRITICAL] offset {a.offset} — {a.campo}: {a.descrizione}")
        for a in warnings:
            print(f"   [WARNING]  offset {a.offset} — {a.campo}: {a.descrizione}")
        for a in infos:
            print(f"   [INFO]     offset {a.offset} — {a.campo}: {a.descrizione}")

    print("=" * 65)
    print(f"  Totale: {len(critiche)} CRITICAL | {len(warnings)} WARNING | {len(infos)} INFO")
    print("=" * 65)

# ─── Funzione core — detect_header_anomaly() ─────────────────────────────────

def detect_header_anomaly(filepath):
    """
    Funzione core del parser differenziale.
    Analizza un file ZIP/APK e restituisce la lista delle anomalie trovate.

    Input:
        filepath (str): percorso al file ZIP o APK

    Output:
        list[dict] — lista di anomalie, ognuna con:
            - severita  : "CRITICAL" | "WARNING" | "INFO"
            - campo     : nome del campo anomalo
            - offset    : offset esatto nel file (stringa hex)
            - valore    : valore trovato
            - descrizione: spiegazione in linguaggio naturale

    Esempio output:
        [
            {
                "severita": "CRITICAL",
                "campo": "signature",
                "offset": "0x00",
                "valore": "64 65 78 0A",
                "descrizione": "DEX magic bytes — possibile APK Janus!"
            }
        ]
    """

    _, anomalie = parse_local_file_header(filepath)

    # Converti lista di oggetti Anomalia in lista di dizionari
    risultato = []
    for a in anomalie:
        risultato.append({
            "severita"   : a.severita,
            "campo"      : a.campo,
            "offset"     : a.offset,
            "valore"     : a.valore,
            "descrizione": a.descrizione
        })

    return risultato


def is_janus(filepath):
    """
    Verifica rapida se un file e un possibile APK Janus.

    Input:
        filepath (str): percorso al file APK

    Output:
        bool — True se DEX magic bytes trovati a offset 0x00
    """

    anomalie = detect_header_anomaly(filepath)
    return any(
        a["campo"] == "signature" and "Janus" in a["descrizione"]
        for a in anomalie
    )


def get_anomalie_by_severita(filepath, severita):
    """
    Restituisce solo le anomalie di una certa severita.

    Input:
        filepath (str): percorso al file
        severita (str): "CRITICAL" | "WARNING" | "INFO"

    Output:
        list[dict] — anomalie filtrate per severita
    """

    anomalie = detect_header_anomaly(filepath)
    return [a for a in anomalie if a["severita"] == severita]

# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 tools/parser_lfh.py <file.zip|file.apk>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"\n[*] Analisi di: {filepath}\n")

    result, anomalie = parse_local_file_header(filepath)

    if result:
        print_lfh(result, anomalie, filepath)
    else:
        print("=" * 65)
        print("  ANALISI FALLITA — ANOMALIE CRITICHE")
        print("=" * 65)
        for a in anomalie:
            print(f"    [CRITICAL] offset {a.offset} — {a.campo}: {a.descrizione}")
        print("=" * 65)


if __name__ == "__main__":
    main()