#!/bin/bash

echo "This script is a still a work in progress, running results in systemd-logind failing to start and getting locked after the Grub menu"
exit 1;

FSTAB_FILE="/etc/fstab"

# update fstab to hidepid
if ! grep -q '^proc' "$FSTAB_FILE"; then
    LINE="proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0"
    
    echo "# 2.4 hidepid - Restrict users to only see their own processes and not those from other users" >> "$FSTAB_FILE"
    echo "$LINE" >> "$FSTAB_FILE"
    echo "Added '$LINE' to $FSTAB_FILE"
else
    echo "hidepid already configured in $FSTAB_FILE"
fi

# Make exception for systemd-logind for user sessions to work correctly
HIDEPID_DIRNAME="/etc/systemd/system/systemd-logind.service.d"
HIDEPID_FILENAME="hidepid.conf"
HIDEPID_PATH="$HIDEPID_DIRNAME/$HIDEPID_FILENAME"

if [ -e "$HIDEPID_PATH" ]; then
    echo "$HIDEPID_PATH already exists. Skipping."
else 
    echo "systemd-logind exception not configured at $HIDEPID_PATH. Creating..."

    if [ ! -e "$HIDEPID_DIRNAME" ]; then
        mkdir -p "$HIDEPID_DIRNAME"
    fi

    touch "$HIDEPID_PATH"

    cat <<EOL >> "$HIDEPID_PATH"
[Service]
SupplementaryGroups=proc
EOL

    cat "$HIDEPID_PATH"
fi
