#!/bin/bash

#
# Options suggested by:
# https://madaidans-insecurities.github.io/guides/linux-hardening.html#sysctl
#
# Use at your own risk.
#

# Check if grubby is installed
if ! command -v grubby &> /dev/null; then
    echo "Error: grubby command not found. Please install grubby."
    exit 1
fi


# Define an array of kernel parameters
declare -a kernel_params=(
    ############
    # Kernel
    ############

    # A kernel pointer points to a specific location in kernel memory. These can be very useful in exploiting the
    # kernel, but kernel pointers are not hidden by default — it is easy to uncover them by, for example, reading
    # the contents of /proc/kallsyms. This setting aims to mitigate kernel pointer leaks. Alternatively, you can
    # set kernel.kptr_restrict=1 to only hide kernel pointers from processes without the CAP_SYSLOG capability.
    "kernel.kptr_restrict=2"

    # dmesg is the kernel log. It exposes a large amount of useful kernel debugging information, but this can often leak
    # sensitive information, such as kernel pointers. Changing the above sysctl restricts the kernel log to the
    # CAP_SYSLOG capability.
    "kernel.dmesg_restrict=1"

    # Despite the value of dmesg_restrict, the kernel log will still be displayed in the console during boot.
    # Malware that is able to record the screen during boot may be able to abuse this to gain higher privileges.
    # This option prevents those information leaks. This must be used in combination with certain boot parameters
    # described below to be fully effective.
    #
    # IMPORTANT: Need to wrap spaced args in quotes, otherwise, it you will boot into cli. Running the --remove-args
    # command will not work as it will leave behind the last 3 3's.
    "kernel.printk='3 3 3 3'"

    # These parameters prevent information leaks during boot and must be used in combination with the kernel.printk sysctl
    # documented above.
    "quiet"
    "loglevel=0"

    # eBPF exposes quite large attack surface. As such, it must be restricted. These sysctls restrict eBPF to the
    # CAP_BPF capability (CAP_SYS_ADMIN on kernel versions prior to 5.8) and enable JIT hardening techniques, such
    # as constant blinding.
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"

    # This restricts loading TTY line disciplines to the CAP_SYS_MODULE capability to prevent unprivileged attackers
    # from loading vulnerable line disciplines with the TIOCSETD ioctl, which has been abused in a number of exploits
    # before.
    "dev.tty.ldisc_autoload=0"

    # The userfaultfd() syscall is often abused to exploit use-after-free flaws. Due to this, this sysctl is used to
    # restrict this syscall to the CAP_SYS_PTRACE capability.
    "vm.unprivileged_userfaultfd=0"

    # kexec is a system call that is used to boot another kernel during runtime. This functionality can be abused to
    # load a malicious kernel and gain arbitrary code execution in kernel mode, so this sysctl disables it.
    "kernel.kexec_load_disabled=1"

    # The SysRq key exposes a lot of potentially dangerous debugging functionality to unprivileged users. Contrary to
    # common assumptions, SysRq is not only an issue for physical attacks, as it can also be triggered remotely. The
    # value of this sysctl makes it so that a user can only use the secure attention key, which will be necessary for
    # accessing root securely. Alternatively, you can simply set the value to 0 to disable SysRq completely.
    "kernel.sysrq=4"

    # User namespaces are a feature in the kernel which aim to improve sandboxing and make it easily accessible for
    # unprivileged users. However, this feature exposes significant kernel attack surface for privilege escalation,
    # so this sysctl restricts the usage of user namespaces to the CAP_SYS_ADMIN capability. For unprivileged
    # sandboxing, it is instead recommended to use a setuid binary with little attack surface to minimise the
    # potential for privilege escalation. This topic is covered further in the sandboxing section.
    #
    # Be aware though that this sysctl only exists on certain Linux distributions, as it requires a kernel patch.
    # If your kernel does not include this patch, you can alternatively disable user namespaces completely
    # (including for root) by setting user.max_user_namespaces=0.
    "kernel.unprivileged_userns_clone=0"

    # Performance events add considerable kernel attack surface and have caused abundant vulnerabilities. This sysctl
    # restricts all usage of performance events to the CAP_PERFMON capability
    # (CAP_SYS_ADMIN on kernel versions prior to 5.8).
    #
    # Be aware that this sysctl also requires a kernel patch that is only available on certain distributions.
    # Otherwise, this setting is equivalent to kernel.perf_event_paranoid=2, which only restricts a subset of this
    # functionality.
    "kernel.perf_event_paranoid=3"



    ###########################
    # Kernel Self-Protection
    ###########################

    # This disables slab merging, which significantly increases the difficulty of heap exploitation by preventing
    # overwriting objects from merged caches and by making it harder to influence slab cache layout.
    "slab_nomerge"

    # This enables zeroing of memory during allocation and free time, which can help mitigate use-after-free
    # vulnerabilities and erase sensitive information in memory.
    "init_on_alloc=1 init_on_free=1"

    # This option randomises page allocator freelists, improving security by making page allocations less
    # predictable. This also improves performance.
    "page_alloc.shuffle=1"

    # This enables Kernel Page Table Isolation, which mitigates Meltdown and prevents some KASLR bypasses.
    "pti=on"

    # This option randomises the kernel stack offset on each syscall, which makes attacks that rely on deterministic
    # kernel stack layout significantly more difficult, such as the exploitation of CVE-2019-18683.
    "randomize_kstack_offset=on"

    # This disables vsyscalls, as they are obsolete and have been replaced with vDSO. vsyscalls are also at fixed
    # addresses in memory, making them a potential target for ROP attacks.
    "vsyscall=none"

    # This disables debugfs, which exposes a lot of sensitive information about the kernel.
    "debugfs=off"

    # Sometimes certain kernel exploits will cause what is known as an "oops". This parameter will cause the kernel to
    # panic on such oopses, thereby preventing those exploits. However, sometimes bad drivers cause harmless oopses
    # which would result in your system crashing, meaning this boot parameter can only be used on certain hardware.
    # "oops=panic"

    # This only allows kernel modules that have been signed with a valid key to be loaded, which increases security by
    # making it much harder to load a malicious kernel module. This prevents all out-of-tree kernel modules, including
    # DKMS modules from being loaded unless you have signed them, meaning that modules such as the VirtualBox or
    # Nvidia drivers may not be usable, although that may not be important, depending on your setup.
    # "module.sig_enforce=1"

    # The kernel lockdown LSM can eliminate many methods that user space code could abuse to escalate to kernel privileges
    # and extract sensitive information. This LSM is necessary to implement a clear security boundary between user space
    # and the kernel. The above option enables this feature in confidentiality mode, the strictest option.
    # This implies module.sig_enforce=1.
    # "lockdown=confidentiality"

    # This causes the kernel to panic on uncorrectable errors in ECC memory which could be exploited. This is unnecessary
    # for systems without ECC memory.
    "mce=0"



    ##########################
    # CPU Mitigations
    ##########################

    # It is best to enable all CPU mitigations that are applicable to your CPU as to ensure that you are not affected by
    # known vulnerabilities. This is a list that enables all built-in mitigations:
    "spectre_v2=on"
    "spec_store_bypass_disable=on"
    "tsx=off"
    "tsx_async_abort=full,nosmt"
    "mds=full,nosmt"
    "l1tf=full,force"
    "nosmt=force"
    "kvm.nx_huge_pages=force"


    #############
    # Network
    #############

    # This helps protect against SYN flood attacks, which are a form of denial-of-service attack, in which an attacker
    # sends a large amount of bogus SYN requests in an attempt to consume enough resources to make the system
    # unresponsive to legitimate traffic.
    "net.ipv4.tcp_syncookies=1"

    # This protects against time-wait assassination by dropping RST packets for sockets in the time-wait state.
    "net.ipv4.tcp_rfc1337=1"

    # These enable source validation of packets received from all interfaces of the machine. This protects against
    # IP spoofing, in which an attacker sends a packet with a fraudulent IP address.
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"


    # Source routing is a mechanism that allows users to redirect network traffic. As this can be used to perform
    # man-in-the-middle attacks in which the traffic is redirected for nefarious purposes, the above settings
    # disable this functionality.
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"

    # This setting makes your system ignore all ICMP requests to avoid Smurf attacks, make the device more difficult
    # to enumerate on the network and prevent clock fingerprinting through ICMP timestamps.
    "net.ipv4.icmp_echo_ignore_all=1"

    # Source routing is a mechanism that allows users to redirect network traffic. As this can be used to perform
    # man-in-the-middle attacks in which the traffic is redirected for nefarious purposes, the above settings
    # disable this functionality.
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"

    # Malicious IPv6 router advertisements can result in a man-in-the-middle attack, so they should be disabled.
    "net.ipv6.conf.all.accept_ra=0"
    "net.ipv6.conf.default.accept_ra=0"

    # This disables TCP SACK. SACK is commonly exploited and unnecessary in many circumstances, so it should be
    # disabled if it is not required.
    "net.ipv4.tcp_sack=0"
    "net.ipv4.tcp_dsack=0"
    "net.ipv4.tcp_fack=0"

    # This disables the entire IPv6 stack which may not be required if you have not migrated to it. 
    # Do not use this boot parameter if you are using IPv6.
    "ipv6.disable=1"



    ##################
    # User space
    ##################


    # ptrace is a system call that allows a program to alter and inspect another running process, which allows
    # attackers to trivially modify the memory of other running programs. This restricts usage of ptrace to only
    # processes with the CAP_SYS_PTRACE capability. Alternatively, set the sysctl to 3 to disable ptrace entirely.
    "kernel.yama.ptrace_scope=2"

    # ASLR is a common exploit mitigation which randomises the position of critical parts of a process in memory.
    # This can make a wide variety of exploits harder to pull off, as they first require an information leak.
    # The above settings increase the bits of entropy used for mmap ASLR, improving its effectiveness.
    #
    # The values of these sysctls must be set in relation to the CPU architecture. The above values are compatible
    # with x86, but other architectures may differ.
    "vm.mmap_rnd_bits=32"
    "vm.mmap_rnd_compat_bits=16"

    # This only permits symlinks to be followed when outside of a world-writable sticky directory, when the owner
    # of the symlink and follower match or when the directory owner matches the symlink's owner. This also prevents
    # hardlinks from being created by users that do not have read/write access to the source file. Both of these
    # prevent many common TOCTOU races.
    "fs.protected_symlinks=1"
    "fs.protected_hardlinks=1"

    # These prevent creating files in potentially attacker-controlled environments, such as world-writable directories,
    # to make data spoofing attacks more difficult.
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
)


# Loop through each kernel parameter
for param_value in "${kernel_params[@]}"; do
    # Check if the parameter already exists
    if grubby --info=ALL | grep -q "$param_value"; then
        echo "Parameter '$param_value' already exists. Skipping."
    else
        # Add the parameter to the kernel command line
        grubby --update-kernel=ALL --args="$param_value"
        echo "Added parameter '$param_value' to kernel command line."
    fi
done

echo "Kernel parameters updated successfully."
echo "Regenerating grub.cfg..."

# Backup file in case of oopsie
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
cp /etc/default/grub "/etc/default/grub-${timestamp}"
cp /boot/grub2/grub.cfg "/boot/grub2/grub-${timestamp}.cfg"

# Update the grub config
grub2-mkconfig -o /boot/grub2/grub.cfg

