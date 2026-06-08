#!/usr/bin/env python3
"""
crea_zip_corrotti.py — Crea 5 ZIP con anomalie intenzionali per testare il parser
Direzione 1 della tesi

Autore: Husam
Data: 2026-05-14
"""

import shutil
import os

# Cartella dove salvare i file corrotti
OUTPUT_DIR = "samples/corrotti"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# File sorgente — usiamo test_stored.zip come base
SOURCE = "test_stored.zip"

def modifica_byte(filepath, offset, nuovi_byte):
    """Modifica i byte a un offset specifico in un file."""
    with open(filepath, 'r+b') as f:
        f.seek(offset)
        f.write(nuovi_byte)

def crea_corrotto(nome, descrizione, offset, nuovi_byte):
    """Copia il file sorgente e applica la corruzione."""
    dest = os.path.join(OUTPUT_DIR, nome)
    shutil.copy(SOURCE, dest)
    modifica_byte(dest, offset, nuovi_byte)
    print(f"✅ Creato: {nome}")
    print(f"   Corruzione: {descrizione}")
    print(f"   Offset: {hex(offset)} — Nuovi byte: {nuovi_byte.hex(' ').upper()}")
    print()

print("=" * 55)
print("  CREAZIONE ZIP CORROTTI — Test parser differenziale")
print("=" * 55)
print()

# ── ZIP 1 — Magic bytes sbagliati ────────────────────────
# Offset 0x00 — cambia 50 4B 03 04 in FF FF FF FF
crea_corrotto(
    "zip1_magic_sbagliati.zip",
    "Magic bytes corrotti: FF FF FF FF invece di 50 4B 03 04",
    0x00,
    b'\xFF\xFF\xFF\xFF'
)

# ── ZIP 2 — DEX magic prepend simulato ───────────────────
# Offset 0x00 — cambia magic in 64 65 78 0A (DEX)
crea_corrotto(
    "zip2_dex_magic.zip",
    "DEX magic bytes: 64 65 78 0A — simula APK Janus",
    0x00,
    b'\x64\x65\x78\x0a'
)

# ── ZIP 3 — CRC32 modificato ─────────────────────────────
# Offset 0x0E — cambia CRC32 in 00 00 00 00
crea_corrotto(
    "zip3_crc32_corrotto.zip",
    "CRC32 azzerato: 00 00 00 00 invece del valore reale",
    0x0E,
    b'\x00\x00\x00\x00'
)

# ── ZIP 4 — compressed_size alterato ─────────────────────
# Offset 0x12 — cambia compressed_size in FF FF FF FF
crea_corrotto(
    "zip4_size_alterato.zip",
    "compressed_size alterato: FF FF FF FF (4294967295 byte)",
    0x12,
    b'\xFF\xFF\xFF\xFF'
)

# ── ZIP 5 — version_needed = 0 ───────────────────────────
# Offset 0x04 — cambia version_needed in 00 00
crea_corrotto(
    "zip5_version_zero.zip",
    "version_needed = 0: valore non standard",
    0x04,
    b'\x00\x00'
)

print("=" * 55)
print(f"  Tutti i file salvati in: {OUTPUT_DIR}/")
print("=" * 55)