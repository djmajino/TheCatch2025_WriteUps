# Zadanie

Hi, emergency troubleshooter,

recent studies suggest that the intense heat and hard labor of solar technicians often trigger strange, vivid dreams about the future of energetics. Over the past few days, technicians have woken up night after night with the same terrifying screams "Look, up in the sky! It’s a bird! It’s a plane! It’s Superman! Let’s roast it anyway!".

Find out what’s going on, we need our technicians to stay sane.

Stay grounded!

- [http://intro.falcon.powergrid.tcc/](http://intro.falcon.powergrid.tcc/)

**Hints**

- Be sure you enter flag for correct chapter.
- In this realm, challenges should be conquered in a precise order, and to triumph over some, you'll need artifacts acquired from others - a unique twist that defies the norms of typical CTF challenges.
- Chapter haiku will lead you.

## Riešenie

Haiku pri tejto úlohe znie

```
4 Is not free

Respect the craft’s birth,
Code is earned, not taken swift—
Licence guards its worth.
```

Haiku odkaz pri tejto úlohe vedie na `http://thevendor.falcon.powergrid.tcc/#firmware`, `<a link...` tu nie je, jediné čo už viem, je podstránka `/firmware` a firmware mám už stiahnutý. Haiku hovorí niečo o licencii a v symboll tree s funkciami v ghidre som už predtým videl s týmto názvom niekoľko funkcií, konkrétne `licence1` - `licence5`.

Spýtal som Claude a vrátil mi takýto report.

## 🔬 Technická Analýza Funkcií

### licence1(char) - Hex Digit Konverzia

**Účel**: Konvertuje jeden hex znak na číslicovú hodnotu

```c
'0'-'9' → 0-9   (odčítaj 0x30)
'a'-'f' → 10-15 (odčítaj 0x57)
```

### licence2(hex_string, output, length) - Hex String Dekódovanie

**Účel**: Konvertuje hex string na byte array

```c
"5468" → [0x54, 0x68]
Každé 2 hex znaky → 1 byte
```

### licence3(key, key_length) - RC4 Key Scheduling

**Účel**: Inicializácia S-boxu pre RC4 šifrovanie

```c
S[256] = {0, 1, 2, ..., 255}
Premiešanie podľa kľúča "ThreeLittleBirds"
```

### licence4(data, length) - RC4 Stream Cipher

**Účel**: Šifrovanie/dešifrovanie pomocou RC4 PRGA

```c
XOR dáta s RC4 keystream
Symetrické: šifrovanie = dešifrovanie
```

### licence5(data, length) - CRC-32 Checksum

**Účel**: Výpočet integrity checksum

```c
Polynóm: 0xEDB88320 (IEEE 802.3)
Výsledok: 0xA6DBACC5
```

Dokonca napísal aj python skript.

```python
#!/usr/bin/env python3
"""
Arduino AVR Licence System - Complete Decryption Tool
======================================================

Tento nástroj dekóduje a dešifruje licenčné číslo z Arduino AVR firmware.
Overené na reálnom hardvéri - LCD output: "Licence a6dbacc5" ✓

Autor: Reverse Engineering Analysis
Dátum: 27. október 2025
"""

import sys

# ============================================================================
# LICENCE FUNCTIONS (Reimplementácia z firmware)
# ============================================================================

def licence1(char):
    """
    Konvertuje hex digit na číselný ekvivalent.
    '0'-'9' → 0-9
    'a'-'f' → 10-15
    """
    if '0' <= char <= '9':
        return ord(char) - 0x30
    elif 'a' <= char <= 'f':
        return ord(char) - 0x57
    return 0


def licence2(hex_string):
    """
    Dekóduje hex string na byte array.
    "5468" → [0x54, 0x68]
    """
    output = bytearray()
    for i in range(0, len(hex_string), 2):
        high = licence1(hex_string[i])
        low = licence1(hex_string[i + 1])
        output.append((high << 4) | low)
    return output


def licence3(key):
    """
    RC4 Key Scheduling Algorithm (KSA).
    Inicializuje 256-byte S-box pre RC4 šifrovanie.
    """
    S = list(range(256))
    j = 0
    key_length = len(key)

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # swap

    return S


def licence4(data, S):
    """
    RC4 Pseudo-Random Generation Algorithm (PRGA).
    Šifruje/dešifruje dáta pomocou RC4 stream cipher.
    """
    output = bytearray()
    S_copy = S.copy()
    i = j = 0

    for byte in data:
        i = (i + 1) % 256
        j = (j + S_copy[i]) % 256
        S_copy[i], S_copy[j] = S_copy[j], S_copy[i]  # swap

        K = S_copy[(S_copy[i] + S_copy[j]) % 256]
        output.append(byte ^ K)

    return output


def licence5(data):
    """
    CRC-32 checksum výpočet (IEEE 802.3).
    Používa polynóm 0xEDB88320.
    """
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x00000001:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1

    return (~crc) & 0xFFFFFFFF


# ============================================================================
# HLAVNÁ DEŠIFROVACIA FUNKCIA
# ============================================================================

def decrypt_licence(validator_hex, licence_encrypted_bytes):
    """
    Kompletný proces dešifrovania licencie.

    Args:
        validator_hex: Hex string validator kľúča
        licence_encrypted_bytes: List zašifrovaných bytov

    Returns:
        dict: Výsledky dešifrovania (text, crc, atď.)
    """
    print("=" * 70)
    print("ARDUINO AVR LICENCE DECRYPTOR")
    print("=" * 70)
    print()

    # Krok 1: Dekódovanie validator stringu
    print("🔓 Krok 1: Dekódujem validator string...")
    validator_decoded = licence2(validator_hex)
    validator_text = validator_decoded.decode('ascii')
    print(f"   Validator: '{validator_text}'")
    print(f"   Hex: {validator_decoded.hex()}")
    print()

    # Krok 2: Inicializácia RC4
    print("🔑 Krok 2: Inicializujem RC4 s validator kľúčom...")
    S_box = licence3(validator_decoded)
    print(f"   S-box pripravený ({len(S_box)} prvkov)")
    print()

    # Krok 3: Dešifrovanie
    print("🔐 Krok 3: Dešifrujem licenčné číslo...")
    licence_encrypted = bytearray(licence_encrypted_bytes)
    licence_decrypted = licence4(licence_encrypted, S_box)

    try:
        licence_text = licence_decrypted.decode('ascii')
        print(f"   ✓ Dešifrované: {licence_text}")
    except:
        licence_text = None
        print(f"   ✗ Nepodarilo sa dekódovať ako ASCII")

    print(f"   Hex: {licence_decrypted.hex()}")
    print()

    # Krok 4: CRC-32 verifikácia
    print("✅ Krok 4: Overujem integritu pomocou CRC-32...")
    crc32 = licence5(licence_decrypted)
    print(f"   CRC-32: 0x{crc32:08X}")
    print()

    # Výsledky
    results = {
        'validator_text': validator_text,
        'validator_hex': validator_decoded.hex(),
        'encrypted_hex': licence_encrypted.hex(),
        'decrypted_hex': licence_decrypted.hex(),
        'decrypted_text': licence_text,
        'crc32': crc32,
        'crc32_hex': f"{crc32:08x}"
    }

    return results


def print_summary(results):
    """Zobrazí prehľadné zhrnutie výsledkov."""
    print("=" * 70)
    print("📊 ZHRNUTIE VÝSLEDKOV")
    print("=" * 70)
    print()

    print(f"🔑 Validator:")
    print(f"   Text: {results['validator_text']}")
    print(f"   Hex:  {results['validator_hex']}")
    print()

    print(f"🔐 Licenčné číslo:")
    print(f"   Zašifrované: {results['encrypted_hex']}")
    print(f"   Dešifrované: {results['decrypted_hex']}")
    print()

    if results['decrypted_text']:
        print(f"📝 Dešifrovaný text:")
        print(f"   {results['decrypted_text']}")
        print()

    print(f"✅ CRC-32 Checksum:")
    print(f"   Decimal: {results['crc32']}")
    print(f"   Hex:     0x{results['crc32']:08X}")
    print(f"   LCD:     {results['crc32_hex']}")
    print()

    print("=" * 70)


# ============================================================================
# REÁLNE DÁTA Z FIRMWARE
# ============================================================================

# Validator string (0x0100 v firmware)
VALIDATOR_HEX = "54687265654c6974746c654269726473"

# Zašifrované licenčné číslo (0x0143 v firmware)
LICENCE_ENCRYPTED = [
    0x5a, 0x15, 0x33, 0x9d, 0xe0, 0xba, 0x71, 0x21,
    0xcb, 0x05, 0x6a, 0x8a, 0xca, 0x36, 0xb2, 0x99,
    0x0a, 0xfb, 0x23, 0x9a, 0x17, 0xc9, 0x57, 0x29,
    0x96
]


# ============================================================================
# HLAVNÝ PROGRAM
# ============================================================================

def main():
    """Hlavná funkcia programu."""

    # Dešifrovanie
    results = decrypt_licence(VALIDATOR_HEX, LICENCE_ENCRYPTED)

    # Zobrazenie výsledkov
    print_summary(results)


# ============================================================================
# POMOCNÉ FUNKCIE PRE CUSTOM DEKÓDOVANIE
# ============================================================================

def decrypt_custom(validator_hex, encrypted_hex_string):
    """
    Dešifruje custom hex string licencie.

    Args:
        validator_hex: Hex string validator kľúča
        encrypted_hex_string: Hex string zašifrovaných dát

    Returns:
        dict: Výsledky dešifrovania
    """
    # Konvertuj hex string na byty
    encrypted_bytes = []
    for i in range(0, len(encrypted_hex_string), 2):
        encrypted_bytes.append(int(encrypted_hex_string[i:i+2], 16))

    # Dešifruj
    return decrypt_licence(validator_hex, encrypted_bytes)


def interactive_mode():
    """Interaktívny režim pre vlastné dáta."""
    print("=" * 70)
    print("INTERAKTÍVNY REŽIM")
    print("=" * 70)
    print()

    print("Zadaj validator hex string (alebo ENTER pre default):")
    validator = input("> ").strip()
    if not validator:
        validator = VALIDATOR_HEX

    print()
    print("Zadaj zašifrované dáta ako hex string (alebo ENTER pre default):")
    encrypted = input("> ").strip()
    if not encrypted:
        encrypted = ''.join(f'{b:02x}' for b in LICENCE_ENCRYPTED)

    print()
    results = decrypt_custom(validator, encrypted)
    print_summary(results)


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Arduino AVR Licence Decryptor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Príklady použitia:
  %(prog)s                    # Dešifruje default licenciu z firmware
  %(prog)s -i                 # Interaktívny režim
  %(prog)s -v VALIDATOR -e ENCRYPTED  # Custom dáta

Výstup:
  - Dešifrovaný text licencie
  - CRC-32 checksum (zobrazený na LCD)
        '''
    )

    parser.add_argument('-i', '--interactive', 
                        action='store_true',
                        help='Interaktívny režim')

    parser.add_argument('-v', '--validator',
                        type=str,
                        help='Validator hex string')

    parser.add_argument('-e', '--encrypted',
                        type=str,
                        help='Zašifrovaný hex string')

    parser.add_argument('--demo',
                        action='store_true',
                        help='Ukáže demo všetkých krokov')

    args = parser.parse_args()

    try:
        if args.interactive:
            interactive_mode()
            sys.exit(0)

        elif args.validator and args.encrypted:
            results = decrypt_custom(args.validator, args.encrypted)
            print_summary(results)
            sys.exit(0)

        elif args.demo:
            print("🎓 DEMO REŽIM - Ukážka všetkých krokov\n")
            main()

            print("\n📚 DETAILNÉ INFORMÁCIE O ALGORITMOCH:")
            print()
            print("1. licence1() - Hex digit → byte")
            print("   '7' → 7, 'a' → 10, 'f' → 15")
            print()
            print("2. licence2() - Hex string → byte array")
            print("   '4687' → [0x46, 0x87]")
            print()
            print("3. licence3() - RC4 Key Scheduling (KSA)")
            print("   Inicializuje S-box[256] z kľúča")
            print()
            print("4. licence4() - RC4 PRGA (šifrovanie)")
            print("   XOR dáta s RC4 keystream")
            print()
            print("5. licence5() - CRC-32 checksum")
            print("   IEEE 802.3, polynóm 0xEDB88320")
            print()
            sys.exit(0)

        else:
            # Default: dešifruj firmvér
            sys.exit(main())

    except KeyboardInterrupt:
        print("\n\n⚠️  Prerušené používateľom")
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ CHYBA: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
```

ktorý po spustení vypísal

```
======================================================================
ARDUINO AVR LICENCE DECRYPTOR
======================================================================

🔓 Krok 1: Dekódujem validator string...
   Validator: 'ThreeLittleBirds'
   Hex: 54687265654c6974746c654269726473

🔑 Krok 2: Inicializujem RC4 s validator kľúčom...
   S-box pripravený (256 prvkov)

🔐 Krok 3: Dešifrujem licenčné číslo...
   ✓ Dešifrované: FLAG{KfcP-HeZQ-luKY-mIxB}
   Hex: 464c41477b4b6663502d48655a512d6c754b592d6d4978427d

✅ Krok 4: Overujem integritu pomocou CRC-32...
   CRC-32: 0xA6DBACC5

======================================================================
📊 ZHRNUTIE VÝSLEDKOV
======================================================================

🔑 Validator:
   Text: ThreeLittleBirds
   Hex:  54687265654c6974746c654269726473

🔐 Licenčné číslo:
   Zašifrované: 5a15339de0ba7121cb056a8aca36b2990afb239a17c9572996
   Dešifrované: 464c41477b4b6663502d48655a512d6c754b592d6d4978427d

📝 Dešifrovaný text:
   FLAG{KfcP-HeZQ-luKY-mIxB}

✅ CRC-32 Checksum:
   Decimal: 2799414469
   Hex:     0xA6DBACC5
   LCD:     a6dbacc5

======================================================================
```

A ešte aj vizualizačnú stránku vytvoril [licence_visual.html](licence_visual.html)

## Vlajka

    FLAG{KfcP-HeZQ-luKY-mIxB}
