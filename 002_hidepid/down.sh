#!/bin/bash

FSTAB_FILE="/etc/fstab"


if ! grep -q '^proc' "$FSTAB_FILE"; then
    echo "hidepid is not configured inside $FSTAB_FILE. No changes made."
else
    # Remove hidepid line & preceding comment
    sed -i '/^# 2.4 hidepid/d' "$FSTAB_FILE"
    sed -i '/^proc/d' "$FSTAB_FILE"

    echo "Removed hidepid config from $FSTAB_FILE"
fi

# Remove systemd-logind exception
HIDEPID_DIRNAME="/etc/systemd/system/systemd-logind.service.d"
HIDEPID_FILENAME="hidepid.conf"
HIDEPID_PATH="$HIDEPID_DIRNAME/$HIDEPID_FILENAME"

if [ -e $HIDEPID_PATH ]; then
    rm "$HIDEPID_PATH"

    echo "Removed $HIDEPID_PATH"
fi
