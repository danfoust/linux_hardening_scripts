#!/bin/bash

FILENAME="/etc/modprobe.d/blacklist.conf"

if [ -e "$FILENAME" ]; then 
    rm "$FILENAME"

    echo "Removed $FILENAME"
else 
    echo "$FILENAME does not exist. No action taken."
fi
