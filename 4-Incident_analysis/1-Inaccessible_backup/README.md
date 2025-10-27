# Zadanie

Hi, emergency troubleshooter,

One of our servers couldn’t withstand the surge of pure energy and burst into bright flames. It is backed up, but no one knows where and how the backups are stored. We only have a memory dump from an earlier investigation available. Find our backups as quickly as possible.

Stay grounded!

- [Download (memory dump for analysis)](inaccessible_backup.zip)

**Súbory**

- [inaccessible_backup.zip](inaccessible_backup.zip)

**Hints**

- The server was running on Debian 12 Bookworm.

## Riešenie

Neviem aké malo byť najoptimálnejšie riešenie a či existuje na to nejaky vhodný nástroj, ale ja som na to šiel na punk cez HxD. Skúsil som vyhľadať string `powergrid.tcc` a našlo mi niekoľko výskytov 

Napríklad

> <78>Sep  3 19:44:01 CRON[12623]: (root) CMD (eval $(keychain --eval --quiet /root/.ssh/backup_key) && /usr/bin/rsync --delete -avz /var/www/html/ bkp@backup.powergrid.tcc:/zfs/backup/www/ > /dev/null 2>&1)

Takýchto podobných je tam mnoho. 

Používa sa rsync na `[bkp@backup.powergrid.tcc](mailto:bkp@backup.powergrid.tcc)` s autorizáciou pomocou kľúča `/root/.ssh/backup_key`. 

Vyhľadaním stringu názvu kľúča mi našlo len cron logy. Ale keď som dal vyhľadať string `BEGIN OPENSSH PRIVATE KEY`, tak mi našlo obsah 4 kľúčov, ktoré som si uložil ako sshkey1 - 4 a pri taktomto množstve to nie je problém poskúšať.

A pri štvrtom s menom [sshkey4](sshkey4) bullseye.

```shell
(base) ctf@ctf:/mnt/c/ctf/TheCatch2025/temp$ chmod 600 ~/sshkey4
(base) ctf@ctf:/mnt/c/ctf/TheCatch2025/temp$ ssh bkp@10.99.25.32 -i ~/sshkey4
The authenticity of host '10.99.25.32 (10.99.25.32)' can't be established.
ED25519 key fingerprint is SHA256:VbQQWe96d0mt5Xxq0J80VwJLEu35TAg37zvQjtEugPA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.99.25.32' (ED25519) to the list of known hosts.
FLAG{VDg1-MfVg-LsJI-NOS4}
Connection to 10.99.25.32 closed.
```

## Vlajka

    FLAG{VDg1-MfVg-LsJI-NOS4}
