# Zadanie

Hi, trainee,

nobody can work secure without VPN. You have to install and configure OpenVPN properly. Configuration file can be downloaded from CTFd's link [VPN](https://www.thecatch.cz/vpn). Your task is to activate VPN, visit the testing pages, and get your code proving your IPv4 and IPv6 readiness.

Stay grounded!

- IPv4 testing page is available at [http://volt.powergrid.tcc](http://volt.powergrid.tcc/).
- IPv6 testing page is available at [http://ampere.powergrid.tcc](http://ampere.powergrid.tcc/).

**Súbory**

- [ctfd_ovpn.ovpn](ctfd_ovpn.ovpn)

**Hints**

- [Installing OpenVPN](https://openvpn.net/community-resources/installing-openvpn/)

## Riešenie

Riešenie je defacto v zadaní úlohy. 

V skratke ide o to, že celé CTF sa odohráva na lokálnej/VPN sieti, do ktorej sa pripojíme pomocou priloženému ovpn profilu.

Vo windowse stačí nainštalovať OpenVPN klienta, naimportovať daný ovpn profil a pripojiť. 

V linuxe, napríklad v debiane, stačí zadať príkaz `sudo openvpn --config ctfd_ovpn.ovpn &` zadať heslo a slobodne používať aj daný terminal tab vďaka `&` na konci príkazu.

Na stránkach zo zadania sa nachádza po polovici vlajky, po zhliadnutí obcoch len spojiť do jedného strongu a hotovo.

# IPv4 VPN Test

Your VPN is IPv4 ready, first part of code is `FLAG{mkuV-TEnW`.

# IPv6 VPN Test

Your VPN is IPv6 ready, second part of code is `-slYz-TFnx}`.

## Vlajka

    FLAG{mkuV-TEnW-slYz-TFnx}
