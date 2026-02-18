#!/bin/sh
# BinAuth script for nodogsplash - called when client attempts to authenticate
# This script always returns success (0) because the real auth is done via gatekeeper.py
#
# Arguments passed by nodogsplash:
# $1 = method (auth_client, client_auth, client_deauth, etc)
# $2 = mac address
# $3 = ip address
# $4+ = additional params

METHOD=$1
MAC=$2
IP=$3

logger -t binauth "Method: $METHOD, MAC: $MAC, IP: $IP"

case "$METHOD" in
    auth_client)
        # Allow all auth requests - the gatekeeper.py handles actual validation
        # and uses ndsctl auth to grant access with proper duration
        exit 0
        ;;
    client_auth)
        exit 0
        ;;
    client_deauth)
        logger -t binauth "Client deauthenticated: $MAC"
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
