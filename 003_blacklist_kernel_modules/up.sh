#!/bin/bash

########################################################################################################################
# 
# Reference: https://madaidans-insecurities.github.io/guides/linux-hardening.html#kasr-kernel-modules
# 
# Summary:
# The kernel allows unprivileged users to indirectly cause certain modules to be loaded via module auto-loading. This 
# allows an attacker to auto-load a vulnerable module which is then exploited. One such example is CVE-2017-6074, in 
# which an attacker could trigger the DCCP kernel module to be loaded by initiating a DCCP connection and then exploit
# a vulnerability in said kernel module.
#
# Specific kernel modules can be blacklisted by inserting files into /etc/modprobe.d with instructions on which kernel 
# modules to blacklist.
#
# The install parameter tells modprobe to run a specific command instead of loading the module as normal. /bin/false is 
# a command that simply returns 1, which will essentially do nothing. Both of these together tells the kernel to run 
# /bin/false instead of loading the module, which will prevent the module from being exploited by attackers. 
# 
# The following are kernel modules that are most likely to be unnecessary: 

FILENAME="/etc/modprobe.d/blacklist.conf"

if [ -e "$FILENAME" ]; then
    echo "$FILENAME already exists. No action will be taken"
else
    touch "$FILENAME"
    cat <<EOL >> "$FILENAME"
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false

# Rare file systems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

# Network file systems
install vivid /bin/false

# Bluetooth
# install bluetooth /bin/false
# install btusb /bin/false

# Webcam
#install uvcvideo /bin/false
EOL

    echo "$FILENAME created"
fi
