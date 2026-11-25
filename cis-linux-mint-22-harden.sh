#!/usr/bin/env bash
# =============================================================================
# CIS Linux Mint 22 Benchmark v1.0.0 — workstation remediation
# =============================================================================
#
# What this is
#   An operator script that applies the workstation recommendations from
#   CIS Linux Mint 22 Benchmark v1.0.0 (benchmark date 2025-08-30, tested by
#   CIS against Linux Mint 22.2). It is not a CIS certified build kit, it
#   does not ship the CIS PDF, and a passing run here is not a certified
#   score. Snapshot or image the machine before the first real run.
#
# How recommendations are mapped
#   Every scored recommendation is one function. The function name is the
#   recommendation id with dots turned into underscores:
#       1.1.1.1  ->  cis_1_1_1_1
#       5.2.3.1.2 -> cis_5_2_3_1_2
#   `./cis-linux-mint-22-harden.sh --list` prints id, level, function, title.
#   `--only 1.4.2 --only 4.1.3` runs just those functions (still subject to
#   Level 2 being off unless --level2 is also set).
#
# Profile
#   Level 1 runs by default. Level 2 is a stricter, more disruptive overlay
#   (separate-partition checks, usb-storage/squashfs/overlay/udf, CUPS,
#   Bluetooth, Avahi, NOPASSWD removal, password aging, auditd, AIDE,
#   journal-upload). Level 2 does not run unless you pass --level2 or
#   APPLY_L2=1. There are 249 controls; 66 of them are Level 2.
#
# What a run actually does
#   1. Parses flags. CLI flags win over environment variables.
#   2. Opens cis-mint22-harden.log in this script's directory (or --log-file).
#   3. Takes an exclusive flock on cis-mint22-harden.lock so two copies
#      cannot edit the same config at once. The lock file is removed when
#      the run exits, including failure and SIGINT/SIGTERM. Only SIGKILL
#      or a power loss leaves the file behind, and a leftover file is not
#      itself a lock. The next run can take it, then removes it on exit.
#   4. Preflight: Linux Mint 22, required commands, free space on /.
#   5. Rejects policy numbers that cannot pass the benchmark audit
#      (for example unlock_time of 300) before any file is changed.
#   6. Walks the controls in benchmark order. Each one logs BEGIN, the
#      work, and END with elapsed seconds.
#   7. Appends one row per control to cis-mint22-results.tsv.
#   8. Runs update-grub once if the kernel command line changed, then
#      re-applies mode 0600 on /boot/grub/grub.cfg (update-grub resets it).
#   9. Prints a reboot checklist and reprints every FAIL, NOT-NEEDED, and
#      MANUAL line so you do not have to hunt the log.
#
# Result words
#   OK        The control was applied, or the system already matched.
#   SKIP      Level 2 is off, or the package/unit this control cares about
#             is not installed and the benchmark says to skip the section.
#   NOT-NEEDED  /tmp, /var/tmp, /home, /var, or /var/log/audit is not its
#             own mount. The recommendation is ignored. No partition is
#             created and fstab is not changed for that path.
#   MANUAL    A person has to decide. Typical reasons: GPG keys, a
#             /var/log partition, GRUB password hash not provided, journal
#             upload URL empty, duplicate UIDs, SUID review, future password
#             dates, X server left installed on purpose.
#   FAIL      The script tried and the command failed, a required tool
#             was missing, or an enabled apt source is not a standard
#             Mint 22 / Ubuntu noble archive. Exit status is 1 if any
#             FAIL occurred. Non-official apt lines are not deleted.
#   A control that prints FAIL is recorded as FAIL. Otherwise MANUAL,
#   otherwise NOT-NEEDED, otherwise SKIP, otherwise OK.
#
# Screen colors (plain text in the log file, no ANSI codes)
#   Green   OK. A control passed, or a command exited 0.
#   Red     FAIL or ERROR. A control failed, or a command exited non-zero.
#           The command's stdout and stderr are logged under that ERROR line.
#   Yellow  INFO, WARN, SKIP, NOT-NEEDED, MANUAL, EXEC, DETAIL, DRY-RUN.
#   Color is on when stdout is a terminal. --color forces it. --no-color
#   turns it off. Each line is stamped:
#       [YYYY-MM-DD HH:MM:SS TZ] [LEVEL] [control-id] message
#
# Files written next to this script
#   cis-mint22-harden.log     Every screen line, appended, one run after another.
#   cis-mint22-results.tsv    run_id, id, level, status, seconds, message.
#   cis-mint22-harden.lock    flock file while a run is in progress.
#                             Deleted when that run exits. If it is still
#                             here and no copy of this script is running,
#                             the last run was killed with SIGKILL. Delete
#                             it, or just run the script again.
#   Config backups, when not a dry-run, go to:
#       /var/backups/cis-mint22-YYYYMMDDHHMMSS/<original path>
#
# Exit codes
#   0   No control failed. MANUAL, NOT-NEEDED, and SKIP do not fail the process.
#   1   At least one FAIL, preflight refusal, or an unexpected abort.
#   2   Bad arguments, unknown --only id, or a policy number outside range.
#   130 Interrupted by SIGINT or SIGTERM. Partial edits may already be on disk.
#
# Safe to re-run
#   The script is written to be idempotent: it rewrites managed drop-in
#   files, comments conflicting keys instead of appending forever, and
#   skips a file write when the new contents match the old. Re-running
#   Level 1 after a successful Level 1 run should mostly log "unchanged"
#   and OK. It will still restart services it owns (ufw, journald) and
#   it will still run `ufw enable` if UFW_ENABLE=1.
#
# Never done automatically
#   Creating /tmp, /home, /var, /var/tmp, /var/log, or /var/log/audit
#     filesystems. /tmp is not turned into a tmpfs. tmp.mount is not
#     unmasked. For /tmp, /var/tmp, /home, /var, and /var/log/audit: if
#     findmnt --mountpoint shows no exact mount, every recommendation for
#     that path is NOT-NEEDED. If the path already is its own mount,
#     missing nodev/nosuid/noexec options are added and the remount is
#     logged with the options from before and after.
#     /var/log is not in that ignore list. If it is not a separate mount
#     the control stays MANUAL. /dev/shm is still given nosuid,nodev,noexec
#     when it is already a mount (it is a tmpfs on a normal system).
#     noexec on /dev/shm breaks some browsers and Electron apps. noexec on
#     a separate /tmp breaks some installers.
#   Removing the X server (2.1.21). A Mint desktop needs xserver-common.
#     --purge-xserver is the only way that package is purged.
#   Purging openssh-server, cups, bluez, avahi-daemon, rsync, rpcbind.
#     Those are masked when installed, which still satisfies "not in use"
#     and is reversible with `systemctl unmask`. Override with the
#     *_ACTION variables below. rsync is masked because Timeshift uses it.
#     rpcbind is masked because libvirt and NFS depend on it.
#   Leaving IPv6 enabled. 3.1.1 now disables it
#     (net.ipv6.conf.all.disable_ipv6=1, default=1, lo=1). --keep-ipv6
#     opts out and leaves 3.1.1 MANUAL. --disable-ipv6 is the default and
#     remains accepted so older command lines still work.
#   Leaving IP forwarding on. 3.3.1 sets net.ipv4.ip_forward=0 and
#     net.ipv6.conf.all/default.forwarding=0, including when IPv6 is
#     disabled, so a later re-enable does not start forwarding.
#   Enabling TCP SYN cookies. CIS 3.3.10 requires
#     net.ipv4.tcp_syncookies=1. This script sets it to 0 because the
#     operator asked for tcp_syn to be disabled. The line is WARN plus OK
#     for the requested value. A CIS audit of 3.3.10 will fail until the
#     sysctl is set back to 1.
#   Deleting or rewriting apt sources. 1.2.1.2 reads sources.list and
#     sources.list.d (one-line and deb822) and scores each enabled entry.
#     Official means packages.linuxmint.com or another *.linuxmint.com
#     host with suite wilma, xia, zara, or zena (Mint 22 through 22.3),
#     or archive.ubuntu.com, *.archive.ubuntu.com, security.ubuntu.com,
#     ports.ubuntu.com, archive.canonical.com, or esm.ubuntu.com with
#     suite noble, noble-updates, noble-security, or noble-backports.
#     HTTP on those hosts is accepted: it is the Mint/Ubuntu default and
#     apt verifies InRelease signatures. Anything else that is enabled
#     (PPA, Debian, NodeSource, cdrom, file:) is FAIL and is left in
#     place. Disabled lines are logged and ignored.
#   `apt-get dist-upgrade`. 1.2.2.1 runs `apt-get update` and then
#     `apt-get upgrade` on every real run. --no-apply-updates skips the
#     upgrade. --no-apt-update skips the index refresh. Neither flag
#     runs dist-upgrade.
#   Installing a GRUB password. Set both GRUB_SUPERUSER and
#     GRUB_PBKDF2_HASH or 1.4.1 is left MANUAL. Generate the hash with:
#       grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64
#     GRUB_UNRESTRICTED=1 (default) adds --unrestricted to CLASS in
#     /etc/grub.d/10_linux so a normal boot does not ask for the password.
#     Editing a menu entry still does. grub-common updates can overwrite
#     10_linux; review it before you reboot.
#   Enabling journal upload. 6.1.2.1.3 stays manual until JOURNAL_UPLOAD_URL
#     and the certificate paths exist. The receiver unit is masked so this
#     host does not accept other hosts' journals.
#   chown of unowned files (7.1.12) unless --fix-unowned.
#   Denylisting every unused filesystem module (1.1.1.10) unless
#     --apply-unused-fs. Unloading a module that is in use can panic.
#   Expiring every password hash (chage -d 0) unless --expire-hashes.
#   Rewriting duplicate UIDs/GIDs/names, root's PATH, or a future
#     "last password change" date. Those are reported.
#
# Workstation-specific choices that differ from a literal purge
#   SSH (2.1.11) is masked, not purged (SSH_ACTION=mask). --purge-ssh
#   purges the package. --keep-ssh leaves the daemon alone and the
#   control is SKIP, which will fail a CIS scan.
#   UFW (section 4) is the only firewall this benchmark scores. The routed
#   policy command is `ufw default disabled routed`, not `ufw default deny
#   routed`. Incoming is deny. Outgoing is left allow (not a numbered
#   recommendation) so the workstation can still reach the network.
#   `ufw enable` runs after the default policies because enable flushes
#   the chains and can drop the SSH session you are using. Add
#   `--allow-ssh` first if you are connected remotely and the daemon
#   will still be listening.
#   Installed updates (1.2.2.1) are `apt-get update` followed by
#     `apt-get upgrade`, not dist-upgrade. That runs by default.
#   Automatic updates (1.2.2.2) use `mintupdate-automation upgrade enable`,
#   not unattended-upgrades. The timer is mintupdate-automation-upgrade.timer.
#   Time sync prefers systemd-timesyncd. If chrony is the only active
#   time daemon, it is left in place and timesyncd is masked (one daemon).
#   NTP servers default to the benchmark's NIST example. Replace
#   NTP_SERVERS and FALLBACK_NTP with your site's servers.
#
# Values that are easy to get wrong
#   faillock unlock_time is 900. The printed remediation sample says 300,
#     but the audit regex accepts only 0 (lock until an admin runs
#     `faillock --user NAME --reset`) or a value from 900 through 604800.
#     900 is the smallest value that passes and still unlocks by itself.
#   faillock deny is 5 (audit allows 1 through 5). The package default is 3.
#   Root lockout (Level 2) sets even_deny_root and root_unlock_time=60
#     (minimum that passes; the sample output shows 300, which is also legal).
#   Password length minlen=14, difok=2, maxrepeat=3, maxsequence=3,
#     remember=24 on pam_pwhistory (not on pam_unix; pam_unix remember=
#     stores history with MD5).
#   Inactive lock is 45 days (INACTIVE=45), not 30. PASS_MAX_DAYS is 365.
#     PASS_MIN_DAYS is 1. PASS_WARN_AGE is 7. ENCRYPT_METHOD is YESCRYPT.
#   auditd on Level 2: max_log_file=8 (site policy, benchmark's stated
#     default), max_log_file_action=keep_logs, disk_full_action=halt,
#     disk_error_action=halt. A full audit disk halts the machine.
#     audit_backlog_limit on the kernel command line is 8192.
#     `-e 2` makes the rules immutable until reboot. --no-audit-immutable
#     skips that line; the benchmark then fails 6.2.3.20.
#   AIDE (Level 2) runs aideinit, which walks the whole disk. --no-aide-init
#     installs the package and the timer but does not build the database.
#
# Reboot
#   The end of the run prints only the reasons that this run actually
#   triggered. Typical ones:
#     GRUB cmdline (apparmor=1 security=apparmor, and on Level 2 audit=1
#       audit_backlog_limit=8192) is not on the running kernel until reboot.
#     AppArmor enforce applies fully after daemons restart; reboot is the
#       reliable way.
#     sysctl files are loaded with sysctl --system during the run, but a
#       reboot proves they stick.
#     PAM changes apply to the next login, not to the current session.
#     LightDM reads greeter-hide-users at start.
#     audit -e 2 does not lock the running rule set until reboot.
#   Do not score the host until after that reboot.
#
# Rollback
#   There is no automatic undo. Restore a file from
#   /var/backups/cis-mint22-<stamp>/ and rerun the service reload that
#   belongs to it (`pam-auth-update`, `update-grub`, `sysctl --system`,
#   `augenrules --load`, `systemctl daemon-reload`). A masked unit comes
#   back with `systemctl unmask` and `systemctl enable --now`. A purged
#   package comes back with `apt-get install`. If `-e 2` was loaded, rule
#   changes wait for a reboot into a config that does not contain it.
#
# High-impact defaults, even on Level 1
#   AppArmor profiles are switched to enforce.
#   IPv6 is disabled. IP forwarding is disabled. TCP SYN cookies are
#     disabled (net.ipv4.tcp_syncookies=0). That last one fails CIS 3.3.10,
#     which wants syncookies enabled.
#   /dev/shm gains nosuid,nodev,noexec when it is already a mount. noexec
#     on /dev/shm breaks some browsers and Electron apps. /tmp options are
#     applied only when /tmp is already a separate mount; otherwise the
#     /tmp recommendations are NOT-NEEDED.
#   UFW is enabled with incoming deny.
#   SSH is masked if openssh-server is installed.
#   apt-get update and apt-get upgrade run (never dist-upgrade).
#   mintupdate will apply later upgrades on its timer.
#   New passwords need 14 characters. faillock locks after 5 failures.
#   The su command is limited to an empty group named sugroup. Nobody can
#     su until you `gpasswd -a USER sugroup`. sudo is unchanged.
#   TMOUT=900 (15 minutes) is exported readonly from /etc/profile.d.
#   Default umask becomes 027.
#
# Usage
#   sudo ./cis-linux-mint-22-harden.sh                  # Level 1
#   sudo ./cis-linux-mint-22-harden.sh --dry-run        # log actions only
#   sudo ./cis-linux-mint-22-harden.sh --level2         # Level 1 + Level 2
#   sudo ./cis-linux-mint-22-harden.sh --only 1.4.2 --only 4.1.3
#   ./cis-linux-mint-22-harden.sh --list
#   sudo ./cis-linux-mint-22-harden.sh --force          # not Mint 22, or low disk
#   sudo ./cis-linux-mint-22-harden.sh --no-ufw-enable --keep-ssh --allow-ssh
#
# Flags (each one overrides the matching environment variable)
#   --level2              Apply Level 2 as well as Level 1.
#   --dry-run             Do not change the system. Root is not required.
#   --list                Print the control catalog and exit.
#   --only ID             Run one recommendation. Repeat for several.
#   --force               Continue when the OS is not Linux Mint 22, or when
#                         / has under 512 MiB free.
#   --purge-xserver       Purge xserver-common. Destroys the graphical desktop.
#   --purge-ssh           Purge openssh-server instead of masking it.
#   --keep-ssh            Do not mask or purge ssh. The control is skipped.
#   --mask-ssh            Mask ssh.socket and ssh.service (the default).
#   --no-ufw-enable       Write UFW policy but do not run `ufw enable`.
#   --allow-ssh           `ufw allow OpenSSH` before enable.
#   --disable-ipv6        Default. Set disable_ipv6=1 on all, default, and lo.
#   --keep-ipv6           Leave IPv6 enabled. 3.1.1 is then MANUAL.
#                         If both flags are passed, the last one wins.
#   --apply-updates       Default. apt-get update, then apt-get upgrade.
#   --no-apply-updates    Do not apt-get upgrade. The index may still refresh
#                         before package installs unless --no-apt-update.
#   --apply-unused-fs     Denylist unused filesystem modules (1.1.1.10).
#   --fix-unowned         chown root:root on unowned files (7.1.12).
#   --journal-rotation    Write the benchmark's example journald size caps.
#   --pwcomplexity        Level 2 manual example: minclass=3.
#   --expire-hashes       chage -d 0 on non-system users (they must reset).
#   --no-aide-init        Skip the slow aideinit database build.
#   --no-audit-immutable  Do not write audit rule `-e 2`.
#   --no-apt-update       Do not apt-get update before installs.
#   --color / --no-color  Force or disable terminal color.
#   --log-file PATH       Append the transcript somewhere else.
#   -h, --help            Print this comment block.
#
# Environment (used when the matching flag is not passed)
#   APPLY_L2=0|1
#   DRY_RUN=0|1
#   FORCE_OS=0|1          same as --force
#   PURGE_UNUSED=1        purge server packages that are not in the keep list
#   SSH_ACTION=mask|purge|skip
#   XSERVER_ACTION=skip|purge
#   CUPS_ACTION=mask|purge|skip          Level 2, default mask
#   BLUETOOTH_ACTION=mask|purge|skip     Level 2, default mask
#   AVAHI_ACTION=mask|purge|skip         Level 2, default mask
#   AUTOFS_ACTION=purge|mask|skip        Level 2, default purge
#   RSYNC_ACTION=mask|purge|skip         default mask (Timeshift)
#   RPCBIND_ACTION=mask|purge|skip       default mask (libvirt, NFS)
#   LDAP_UTILS_ACTION=purge|skip         skipped automatically if sssd is installed
#   UFW_ENABLE=1
#   UFW_ALLOW_SSH=0
#   DISABLE_IPV6=1        0, or --keep-ipv6, leaves IPv6 enabled
#   APPLY_UPDATES=1       0 or --no-apply-updates skips apt-get upgrade
#   APT_UPDATE=1          0 or --no-apt-update skips apt-get update
#   APPLY_UNUSED_FS=0
#   FIX_UNOWNED=0
#   APPLY_JOURNAL_ROTATION=0
#   APPLY_PWCOMPLEXITY=0
#   EXPIRE_HASHES=0
#   AIDE_INIT=1
#   AUDIT_IMMUTABLE=1
#   AUDIT_MAX_LOG_FILE=8
#   GRUB_SUPERUSER=
#   GRUB_PBKDF2_HASH=
#   GRUB_UNRESTRICTED=1
#   NTP_SERVERS=time.nist.gov
#   FALLBACK_NTP="time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov"
#   TIME_SYNC=auto|timesyncd|chrony
#   SU_GROUP=sugroup
#   BANNER_TEXT="Authorized users only. All activity may be monitored and reported."
#   TMPFS_SIZE=2G         no longer used. /tmp tmpfs is not created.
#   SHM_SIZE=2G
#   TMOUT_SECONDS=900     integer 1..900
#   PASS_MAX_DAYS=365     Level 2, integer 1..365, must be greater than PASS_MIN_DAYS
#   PASS_MIN_DAYS=1       Level 2, integer >= 1
#   PASS_WARN_AGE=7       integer >= 7
#   INACTIVE_DAYS=45      Level 2, integer 0..45
#   FAILLOCK_DENY=5       integer 1..5
#   FAILLOCK_UNLOCK_TIME=900   0, or 900..604800. 300 does not pass the audit.
#   ROOT_UNLOCK_TIME=60   Level 2, integer >= 60
#   PW_MINLEN=14          integer >= 14
#   PW_DIFOK=2            integer >= 2
#   PW_MAXREPEAT=3        integer 1..3
#   PW_MAXSEQUENCE=3      integer 1..3
#   PW_REMEMBER=24        integer >= 24
#   JOURNAL_UPLOAD_URL=
#   JOURNAL_SERVER_KEY=/etc/ssl/private/journal-upload.pem
#   JOURNAL_SERVER_CERT=/etc/ssl/certs/journal-upload.pem
#   JOURNAL_TRUSTED_CERT=/etc/ssl/ca/trusted.pem
#   LOG_FILE=             default: <directory of this script>/cis-mint22-harden.log
#
# Section order inside the script
#   1.1  Filesystem modules and mount options. Missing /tmp, /var/tmp,
#        /home, /var, and /var/log/audit mounts are NOT-NEEDED, not created.
#   1.2  Package manager. GPG keys are listed, not deleted. Enabled apt
#        sources are compared to official Mint 22 and Ubuntu noble archives
#        and are not rewritten.
#   1.3  AppArmor packages, GRUB cmdline, aa-enforce.
#   1.4  GRUB superuser (only with a hash) and grub.cfg mode 0600.
#   1.5  ASLR, ptrace_scope=1, suid_dumpable=0, core dumps off, no prelink,
#        apport disabled and masked.
#   1.6  Banners without OS tokens. Legal text is BANNER_TEXT.
#   1.7  Cinnamon / LightDM: hide the user list, lock after idle, no autorun.
#        Screen lock is also written as a dconf lock so it is not only the
#        current user's gsettings.
#   2.1  Server services that should not be listening.
#   2.2  Legacy clients (nis, rsh, talk, telnet, ldap-utils, ftp).
#   2.3  One time daemon.
#   2.4  cron and at permissions. cron.allow is mode 0640, group crontab
#        when that group exists. Directories under /etc/cron.* are 0700.
#   3.1  IPv6 disabled by default. Bluetooth (Level 2).
#   3.2  Disable dccp, tipc, rds, sctp.
#   3.3  Host sysctl. Forwarding off. Redirects, rp_filter, martians.
#        tcp_syncookies is set to 0 (site override of CIS, which wants 1).
#        IPv6 router-advertisement sysctls are skipped when IPv6 is off.
#   4.1  gufw/ufw.
#   5.1  sudo use_pty, sudo log, timestamp_timeout only if the current value
#        is negative or greater than 15, su restricted to an empty group.
#   5.2  PAM: unix, faillock, pwquality, pwhistory, via pam-auth-update
#        profiles in /usr/share/pam-configs. common-* is not hand-edited.
#   5.3  login.defs, account aging (Level 2), root checks, TMOUT, umask.
#   6.1  journald persistent, compressed, not forwarded to syslog.
#   6.2  auditd (Level 2), rules under /etc/audit/rules.d, -e 2 last.
#   6.3  AIDE (Level 2) including the audit tools in aide.conf.
#   7.1  passwd/group/shadow modes, world-writable fixup, unowned report,
#        SUID/SGID report.
#   7.2  Shadowed passwords, empty passwords locked, home directories 0750
#        or tighter, dotfile modes. .forward and .rhosts are reported, not
#        deleted.
#
# After you run it
#   Read the action list at the bottom of the log. Fix every FAIL.
#   Read every NOT-NEEDED line: those mounts were not separate, so the
#   benchmark item was ignored on purpose.
#   Read every MANUAL and either do the work or record a site exception.
#   Reboot if the checklist says so. Then run the benchmark audit against
#   the host. Do not treat this script's OK lines as the audit.
# =============================================================================
# END_HEADER
set -uo pipefail

APPLY_L2="${APPLY_L2:-0}"
DRY_RUN="${DRY_RUN:-0}"
FORCE_OS="${FORCE_OS:-0}"
PURGE_UNUSED="${PURGE_UNUSED:-1}"
SSH_ACTION="${SSH_ACTION:-mask}"
XSERVER_ACTION="${XSERVER_ACTION:-skip}"
CUPS_ACTION="${CUPS_ACTION:-mask}"
BLUETOOTH_ACTION="${BLUETOOTH_ACTION:-mask}"
AVAHI_ACTION="${AVAHI_ACTION:-mask}"
AUTOFS_ACTION="${AUTOFS_ACTION:-purge}"
RSYNC_ACTION="${RSYNC_ACTION:-mask}"
RPCBIND_ACTION="${RPCBIND_ACTION:-mask}"
LDAP_UTILS_ACTION="${LDAP_UTILS_ACTION:-purge}"
UFW_ENABLE="${UFW_ENABLE:-1}"
UFW_ALLOW_SSH="${UFW_ALLOW_SSH:-0}"
DISABLE_IPV6="${DISABLE_IPV6:-1}"
APPLY_UPDATES="${APPLY_UPDATES:-1}"
APT_UPDATE="${APT_UPDATE:-1}"
APPLY_UNUSED_FS="${APPLY_UNUSED_FS:-0}"
FIX_UNOWNED="${FIX_UNOWNED:-0}"
APPLY_JOURNAL_ROTATION="${APPLY_JOURNAL_ROTATION:-0}"
APPLY_PWCOMPLEXITY="${APPLY_PWCOMPLEXITY:-0}"
EXPIRE_HASHES="${EXPIRE_HASHES:-0}"
AIDE_INIT="${AIDE_INIT:-1}"
AUDIT_IMMUTABLE="${AUDIT_IMMUTABLE:-1}"
AUDIT_MAX_LOG_FILE="${AUDIT_MAX_LOG_FILE:-8}"
GRUB_SUPERUSER="${GRUB_SUPERUSER:-}"
GRUB_PBKDF2_HASH="${GRUB_PBKDF2_HASH:-}"
GRUB_UNRESTRICTED="${GRUB_UNRESTRICTED:-1}"
NTP_SERVERS="${NTP_SERVERS:-time.nist.gov}"
FALLBACK_NTP="${FALLBACK_NTP:-time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov}"
TIME_SYNC="${TIME_SYNC:-auto}"
SU_GROUP="${SU_GROUP:-sugroup}"
BANNER_TEXT="${BANNER_TEXT:-Authorized users only. All activity may be monitored and reported.}"
TMPFS_SIZE="${TMPFS_SIZE:-2G}"
SHM_SIZE="${SHM_SIZE:-2G}"
TMOUT_SECONDS="${TMOUT_SECONDS:-900}"
PASS_MAX_DAYS="${PASS_MAX_DAYS:-365}"
PASS_MIN_DAYS="${PASS_MIN_DAYS:-1}"
PASS_WARN_AGE="${PASS_WARN_AGE:-7}"
INACTIVE_DAYS="${INACTIVE_DAYS:-45}"
FAILLOCK_DENY="${FAILLOCK_DENY:-5}"
FAILLOCK_UNLOCK_TIME="${FAILLOCK_UNLOCK_TIME:-900}"
ROOT_UNLOCK_TIME="${ROOT_UNLOCK_TIME:-60}"
PW_MINLEN="${PW_MINLEN:-14}"
PW_DIFOK="${PW_DIFOK:-2}"
PW_MAXREPEAT="${PW_MAXREPEAT:-3}"
PW_MAXSEQUENCE="${PW_MAXSEQUENCE:-3}"
PW_REMEMBER="${PW_REMEMBER:-24}"
JOURNAL_UPLOAD_URL="${JOURNAL_UPLOAD_URL:-}"
JOURNAL_SERVER_KEY="${JOURNAL_SERVER_KEY:-/etc/ssl/private/journal-upload.pem}"
JOURNAL_SERVER_CERT="${JOURNAL_SERVER_CERT:-/etc/ssl/certs/journal-upload.pem}"
JOURNAL_TRUSTED_CERT="${JOURNAL_TRUSTED_CERT:-/etc/ssl/ca/trusted.pem}"
LOG_FILE="${LOG_FILE:-}"
USE_COLOR="${USE_COLOR:-auto}"
SCRIPT_DIR=""
CURRENT_ID=""
NORMAL_EXIT=0
LOCK_HELD=0
LOCK_PATH=""
RUN_ID=""
LOGGING_READY=0
RESULTS_FILE=""
C_RESET=""
C_GREEN=""
C_RED=""
C_YELLOW=""

declare -a CONTROL_ORDER=()
declare -A CONTROL_LEVEL=()
declare -A CONTROL_FUNC=()
declare -A CONTROL_DESC=()
declare -A ONLY_SET=()
declare -a MANUAL_NOTES=()
declare -a NOTNEEDED_NOTES=()
declare -a FAIL_NOTES=()
declare -a REBOOT_REASONS=()
ONLY_MODE=0
LIST_ONLY=0
DO_APT_UPDATE=1

declare -i N_OK=0 N_SKIP=0 N_MANUAL=0 N_NOTNEEDED=0 N_FAIL=0 N_CMD_FAIL=0
GRUB_DIRTY=0
BACKUP_DIR=""
TIME_DAEMON=""
declare -a GRUB_ADDITIONS=()

APT_GET=(apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

usage() {
  local line
  while IFS= read -r line; do
    [[ "$line" == "# END_HEADER" ]] && break
    [[ "$line" == "#!"* ]] && continue
    line="${line#\#}"
    line="${line# }"
    if [[ "${LOGGING_READY:-0}" == 1 ]]; then
      emit INFO "$line"
    else
      printf '%s\n' "$line"
    fi
  done < "$0"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --level2) APPLY_L2=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --list) LIST_ONLY=1 ;;
      --force) FORCE_OS=1 ;;
      --only)
        shift
        [[ $# -ge 1 ]] || die "missing id after --only" 2
        ONLY_SET["$1"]=1
        ONLY_MODE=1
        ;;
      --purge-xserver) XSERVER_ACTION=purge ;;
      --purge-ssh) SSH_ACTION=purge ;;
      --keep-ssh) SSH_ACTION=skip ;;
      --mask-ssh) SSH_ACTION=mask ;;
      --no-ufw-enable) UFW_ENABLE=0 ;;
      --allow-ssh) UFW_ALLOW_SSH=1 ;;
      --disable-ipv6) DISABLE_IPV6=1 ;;
      --keep-ipv6) DISABLE_IPV6=0 ;;
      --apply-updates) APPLY_UPDATES=1 ;;
      --no-apply-updates) APPLY_UPDATES=0 ;;
      --apply-unused-fs) APPLY_UNUSED_FS=1 ;;
      --fix-unowned) FIX_UNOWNED=1 ;;
      --journal-rotation) APPLY_JOURNAL_ROTATION=1 ;;
      --pwcomplexity) APPLY_PWCOMPLEXITY=1 ;;
      --expire-hashes) EXPIRE_HASHES=1 ;;
      --no-aide-init) AIDE_INIT=0 ;;
      --no-audit-immutable) AUDIT_IMMUTABLE=0 ;;
      --no-apt-update) APT_UPDATE=0 ;;
      --color) USE_COLOR=1 ;;
      --no-color) USE_COLOR=0 ;;
      --log-file)
        shift
        [[ $# -ge 1 ]] || die "missing path after --log-file" 2
        LOG_FILE="$1"
        ;;
      -h|--help) usage; NORMAL_EXIT=1; exit 0 ;;
      *) emit ERROR "unknown argument: $1"; usage; NORMAL_EXIT=1; exit 2 ;;
    esac
    shift
  done
}

init_logging() {
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
  if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="${SCRIPT_DIR}/cis-mint22-harden.log"
  fi
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  if ! touch "$LOG_FILE" 2>/dev/null; then
    echo "cannot write log file: $LOG_FILE" >&2
    exit 1
  fi
  chmod 0640 "$LOG_FILE" 2>/dev/null || chmod 0644 "$LOG_FILE" 2>/dev/null || true
  LOGGING_READY=1
}

resolve_color() {
  if [[ "$USE_COLOR" == auto ]]; then
    if [[ -t 1 ]]; then USE_COLOR=1; else USE_COLOR=0; fi
  fi
  if [[ "$USE_COLOR" == 1 ]]; then
    C_RESET=$'\033[0m'
    C_GREEN=$'\033[32m'
    C_RED=$'\033[31m'
    C_YELLOW=$'\033[33m'
  else
    C_RESET="" C_GREEN="" C_RED="" C_YELLOW=""
  fi
}

color_for_level() {
  case "$1" in
    OK) printf '%s' "$C_GREEN" ;;
    FAIL|ERROR) printf '%s' "$C_RED" ;;
    *) printf '%s' "$C_YELLOW" ;;
  esac
}

emit() {
  local level="$1"
  shift
  local msg="$*" ts plain color ctx=""
  ts="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  [[ -n "${CURRENT_ID}" ]] && ctx=" [${CURRENT_ID}]"
  plain="[${ts}] [${level}]${ctx} ${msg}"
  color="$(color_for_level "$level")"
  if [[ "$USE_COLOR" == 1 ]]; then
    printf '%s%s%s\n' "$color" "$plain" "$C_RESET"
  else
    printf '%s\n' "$plain"
  fi
  [[ -n "$LOG_FILE" ]] && printf '%s\n' "$plain" >> "$LOG_FILE" || true
}

log()     { emit INFO "$*"; }
ok()        { emit OK "$*"; N_OK+=1; }
skip()      { emit SKIP "$*"; N_SKIP+=1; }
notneeded() { emit NOT-NEEDED "$*"; N_NOTNEEDED+=1; NOTNEEDED_NOTES+=("$*"); }
manual()    { emit MANUAL "$*"; N_MANUAL+=1; MANUAL_NOTES+=("$*"); }
fail()      { emit FAIL "$*"; N_FAIL+=1; FAIL_NOTES+=("$*"); }
warn()    { emit WARN "$*"; }
detail()  { emit DETAIL "$*"; }

die() {
  local status=1
  if [[ $# -ge 2 && "${!#}" =~ ^[0-9]+$ ]]; then
    status="${!#}"
    set -- "${@:1:$#-1}"
  fi
  emit ERROR "$*"
  NORMAL_EXIT=1
  exit "$status"
}

quote_cmd() {
  local out="" a
  for a in "$@"; do
    out+="$(printf '%q' "$a") "
  done
  printf '%s' "${out% }"
}

note_reboot() {
  local reason="$1" r
  if ((${#REBOOT_REASONS[@]})); then
    for r in "${REBOOT_REASONS[@]}"; do
      [[ "$r" == "$reason" ]] && return 0
    done
  fi
  REBOOT_REASONS+=("$reason")
  emit WARN "reboot will be required: ${reason}"
}

on_signal() {
  emit ERROR "received ${1}. Stopping. Partial changes may already be applied. Log: ${LOG_FILE}"
  NORMAL_EXIT=1
  release_lock
  exit 130
}

on_exit() {
  local rc=$?
  release_lock
  [[ "${NORMAL_EXIT}" == 1 ]] && return 0
  if [[ "$rc" -ne 0 ]]; then
    emit ERROR "script stopped unexpectedly with status ${rc}. Log: ${LOG_FILE}"
  fi
}

register() {
  local id="$1" level="$2" fn="$3" desc="$4"
  CONTROL_ORDER+=("$id")
  CONTROL_LEVEL["$id"]="$level"
  CONTROL_FUNC["$id"]="$fn"
  CONTROL_DESC["$id"]="$desc"
}

run_cmd() {
  local rc=0 elapsed=0 start now quoted line tmp
  quoted="$(quote_cmd "$@")"
  if [[ "$DRY_RUN" == 1 ]]; then
    emit DRY-RUN "would run: ${quoted}"
    return 0
  fi
  emit EXEC "running: ${quoted}"
  start="$(date +%s)"
  tmp="$(mktemp)"
  set +e
  "$@" >"$tmp" 2>&1
  rc=$?
  set +e
  now="$(date +%s)"
  elapsed="$((now - start))"
  if [[ -s "$tmp" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$rc" -eq 0 ]]; then emit DETAIL "  | ${line}"; else emit ERROR "  | ${line}"; fi
    done < "$tmp"
  else
    emit DETAIL "  | (no output)"
  fi
  rm -f "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    emit OK "command succeeded in ${elapsed}s (exit 0): ${quoted}"
  else
    N_CMD_FAIL+=1
    emit ERROR "command failed in ${elapsed}s (exit ${rc}): ${quoted}"
  fi
  return "$rc"
}

backup_file() {
  local f="$1" rel
  [[ -e "$f" ]] || return 0
  [[ "$DRY_RUN" == 1 ]] && return 0
  [[ -n "$BACKUP_DIR" ]] || return 0
  rel="${f#/}"
  mkdir -p "$BACKUP_DIR/$(dirname "$rel")"
  if cp -a "$f" "$BACKUP_DIR/$rel" 2>/dev/null; then
    emit INFO "backed up ${f} -> ${BACKUP_DIR}/${rel}"
  else
    emit ERROR "backup failed for ${f}"
  fi
}

write_file() {
  local dest="$1" mode="$2" tmp line
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ "$DRY_RUN" == 1 ]]; then
    emit DRY-RUN "would write ${dest} mode ${mode} ($(wc -c < "$tmp" | tr -d ' ') bytes)"
    while IFS= read -r line || [[ -n "$line" ]]; do
      emit DETAIL "    | ${line}"
    done < "$tmp"
    rm -f "$tmp"
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  if [[ -e "$dest" ]] && cmp -s "$tmp" "$dest"; then
    emit INFO "unchanged ${dest}"
    rm -f "$tmp"
    return 0
  fi
  [[ -e "$dest" ]] && backup_file "$dest"
  if ! install -m "$mode" -o root -g root "$tmp" "$dest"; then
    rm -f "$tmp"
    fail "could not write ${dest} (mode ${mode})"
    return 1
  fi
  rm -f "$tmp"
  emit OK "wrote ${dest} mode ${mode}"
}

pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

apt_update_once() {
  [[ "$DO_APT_UPDATE" == 1 ]] || return 0
  DO_APT_UPDATE=0
  [[ "$APT_UPDATE" == 1 ]] || return 0
  if ! run_cmd env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" update; then
    warn "apt-get update failed; retrying once"
    DO_APT_UPDATE=0
    run_cmd env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" update || fail "apt-get update failed twice; later installs may fail offline"
  fi
}

apt_install() {
  apt_update_once
  run_cmd env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" install "$@"
}

apt_purge() {
  run_cmd env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" purge "$@"
}

uid_min() {
  awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2; exit}' /etc/login.defs 2>/dev/null || echo 1000
}

ipv6_enabled() {
  [[ "$DISABLE_IPV6" == 1 ]] && return 1
  if [[ -r /sys/module/ipv6/parameters/disable ]] && [[ "$(cat /sys/module/ipv6/parameters/disable)" == 1 ]]; then
    return 1
  fi
  local v
  v="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
  [[ "$v" == 1 ]] && return 1
  return 0
}

set_kv() {
  local file="$1" key="$2" value="$3" style="${4:-=}"
  [[ "$DRY_RUN" == 1 ]] && { log "DRY-RUN: set ${key} ${style} ${value} in ${file}"; return 0; }
  mkdir -p "$(dirname "$file")"
  [[ -e "$file" ]] || touch "$file"
  backup_file "$file"
  if [[ "$style" == "=" ]]; then
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
      sed -ri "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
      printf '%s\n' "${key} = ${value}" >> "$file"
    fi
  else
    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$file"; then
      sed -ri "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$file"
    else
      printf '%s\n' "${key} ${value}" >> "$file"
    fi
  fi
}

comment_active_key() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  [[ "$DRY_RUN" == 1 ]] && { log "DRY-RUN: comment ${key} in ${file}"; return 0; }
  backup_file "$file"
  sed -ri "s|^([[:space:]]*${key}[[:space:]]*([=[:space:]]).*)|# cis-disabled: \\1|" "$file"
}

sysctl_set() {
  local key="$1" value="$2" file="$3" other current after
  current="$(sysctl -n "$key" 2>/dev/null || echo '(unreadable)')"
  detail "sysctl ${key}: running_before=${current} target=${value} persist=${file}"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: would set ${key} = ${value} in ${file} (running value stays ${current})"
    return 0
  fi
  mkdir -p /etc/sysctl.d
  [[ -e "$file" ]] || touch "$file"
  backup_file "$file"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -ri "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '%s\n' "${key} = ${value}" >> "$file"
  fi
  detail "sysctl ${key}: wrote '${key} = ${value}' to ${file}"
  for other in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
    [[ -f "$other" && "$other" != "$file" ]] || continue
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$other"; then
      backup_file "$other"
      sed -ri "s|^([[:space:]]*${key}[[:space:]]*=.*)|# cis-disabled: \\1|" "$other"
      detail "sysctl ${key}: commented the active assignment in ${other}"
    fi
  done
  if sysctl -w "${key}=${value}" >/dev/null 2>&1; then
    after="$(sysctl -n "$key" 2>/dev/null || echo '(unreadable)')"
    detail "sysctl ${key}: running_after=${after}"
    if [[ "$after" != "$value" ]]; then
      warn "sysctl ${key} reads ${after} after setting ${value}"
    fi
  else
    warn "sysctl -w ${key}=${value} failed. Value remains in ${file}; the final sysctl --system retries it."
  fi
  note_reboot "sysctl drop-ins under /etc/sysctl.d were changed. sysctl --system loads them now; reboot confirms they survive."
}

require_int() {
  local name="$1" val="$2" min="$3" max="$4"
  if ! [[ "$val" =~ ^[0-9]+$ ]]; then
    die "${name} must be an integer, got '${val}'" 2
  fi
  if (( val < min || val > max )); then
    die "${name}=${val} is outside ${min}..${max}. Refusing to write a value the benchmark audit would fail." 2
  fi
}

validate_policy() {
  require_int FAILLOCK_DENY "$FAILLOCK_DENY" 1 5
  if [[ "$FAILLOCK_UNLOCK_TIME" != 0 ]]; then
    require_int FAILLOCK_UNLOCK_TIME "$FAILLOCK_UNLOCK_TIME" 900 604800
  fi
  require_int ROOT_UNLOCK_TIME "$ROOT_UNLOCK_TIME" 60 604800
  require_int PW_MINLEN "$PW_MINLEN" 14 72
  require_int PW_DIFOK "$PW_DIFOK" 2 10
  require_int PW_MAXREPEAT "$PW_MAXREPEAT" 1 3
  require_int PW_MAXSEQUENCE "$PW_MAXSEQUENCE" 1 3
  require_int PW_REMEMBER "$PW_REMEMBER" 24 400
  require_int PASS_MAX_DAYS "$PASS_MAX_DAYS" 1 365
  require_int PASS_MIN_DAYS "$PASS_MIN_DAYS" 1 364
  require_int PASS_WARN_AGE "$PASS_WARN_AGE" 7 90
  require_int INACTIVE_DAYS "$INACTIVE_DAYS" 0 45
  require_int TMOUT_SECONDS "$TMOUT_SECONDS" 1 900
  require_int AUDIT_MAX_LOG_FILE "$AUDIT_MAX_LOG_FILE" 1 1024
  if (( PASS_MAX_DAYS <= PASS_MIN_DAYS )); then
    die "PASS_MAX_DAYS (${PASS_MAX_DAYS}) must be greater than PASS_MIN_DAYS (${PASS_MIN_DAYS})" 2
  fi
  emit INFO "policy numbers accepted: deny=${FAILLOCK_DENY} unlock_time=${FAILLOCK_UNLOCK_TIME} minlen=${PW_MINLEN} remember=${PW_REMEMBER} max_days=${PASS_MAX_DAYS} inactive=${INACTIVE_DAYS} tmout=${TMOUT_SECONDS}"
}

preflight() {
  local id="" version="" name="" pretty="" missing=0 cmd avail
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
    pretty="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")"
  fi
  emit INFO "detected OS: ${pretty:-unknown} (ID=${id:-?} VERSION_ID=${version:-?})"
  if [[ "$id" != "linuxmint" || "$version" != 22* ]]; then
    if [[ "$FORCE_OS" == 1 ]]; then
      warn "OS is not Linux Mint 22. --force was given; continuing on ${pretty:-this OS}."
    elif [[ "$DRY_RUN" == 1 ]]; then
      warn "OS is not Linux Mint 22. Dry-run continues. A real run needs --force on this OS."
    else
      die "This script targets Linux Mint 22. Detected '${pretty:-unknown}'. Pass --force only if you accept the mismatch." 1
    fi
  fi
  for cmd in awk sed grep find install chmod chown; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      emit ERROR "required command missing: ${cmd}"
      missing=1
    fi
  done
  if [[ "$DRY_RUN" != 1 ]]; then
    for cmd in systemctl apt-get dpkg-query; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        emit ERROR "required command missing: ${cmd}"
        missing=1
      fi
    done
  fi
  [[ "$missing" == 0 ]] || die "preflight failed: install the missing commands and rerun" 1
  avail="$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ "$avail" =~ ^[0-9]+$ ]]; then
    emit INFO "free space on / : ${avail} MiB"
    if (( avail < 512 )) && [[ "$DRY_RUN" != 1 && "$FORCE_OS" != 1 ]]; then
      die "less than 512 MiB free on /. Free space or pass --force." 1
    elif (( avail < 2048 )); then
      warn "less than 2 GiB free on /. Package installs and AIDE may fail."
    fi
  else
    warn "could not read free space on /"
  fi
}

acquire_lock() {
  LOCK_PATH="${SCRIPT_DIR}/cis-mint22-harden.lock"
  # Append, do not truncate. Truncating would race with a holder.
  exec 9>>"$LOCK_PATH" || die "cannot open lock ${LOCK_PATH}" 1
  if ! flock -n 9; then
    exec 9>&- || true
    die "another cis-linux-mint-22-harden.sh holds ${LOCK_PATH}. Wait for it to finish. The file is removed when that run exits." 1
  fi
  LOCK_HELD=1
  printf 'pid=%s run=%s started=%s\n' "$$" "${RUN_ID}" "$(date '+%Y-%m-%d %H:%M:%S %Z')" >&9 || true
  emit INFO "lock acquired: ${LOCK_PATH} (pid $$, removed when this run exits)"
}

release_lock() {
  [[ "${LOCK_HELD:-0}" == 1 ]] || return 0
  local lock="${LOCK_PATH}"
  LOCK_HELD=0
  # Unlink while this process still holds the flock, so a later run's
  # new lock file is not the one removed.
  if [[ -n "$lock" ]] && rm -f -- "$lock"; then
    emit INFO "lock removed: ${lock}"
  else
    emit ERROR "could not remove lock ${lock:-<unset>}"
  fi
  flock -u 9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
}

init_results() {
  RESULTS_FILE="${SCRIPT_DIR}/cis-mint22-results.tsv"
  if [[ ! -s "$RESULTS_FILE" ]]; then
    printf '%s\n' $'run_id\tid\tlevel\tstatus\tseconds\tmessage' > "$RESULTS_FILE"
  fi
  emit INFO "results file: ${RESULTS_FILE}"
}

write_result() {
  local id="$1" level="$2" status="$3" secs="$4" msg="$5"
  msg="${msg//$'\t'/ }"
  msg="${msg//$'\n'/ }"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$RUN_ID" "$id" "$level" "$status" "$secs" "$msg" >> "$RESULTS_FILE"
}

modprobe_disable() {
  local id="$1" mod="$2" bl="$3"
  local conf="/etc/modprobe.d/60-${bl}.conf"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: ${id} unload ${mod}; write ${conf}"
    ok "${id} ${mod} disabled (dry-run)"
    return 0
  fi
  modprobe -r "$mod" 2>/dev/null || true
  rmmod "$mod" 2>/dev/null || true
  write_file "$conf" 644 <<EOF
install ${bl} /bin/false
blacklist ${bl}
EOF
  ok "${id} ${mod} blacklisted as ${bl} in ${conf}"
}

fstab_add_opts() {
  local mp="$1"; shift
  local -a want=("$@")
  local tmp line src tgt fst opts dump pass opt found=0
  [[ -f /etc/fstab ]] || return 2
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*# || -z "${line//[[:space:]]/}" ]]; then
      printf '%s\n' "$line" >> "$tmp"
      continue
    fi
    read -r src tgt fst opts dump pass <<<"$line"
    if [[ "$tgt" == "$mp" ]]; then
      found=1
      for opt in "${want[@]}"; do
        case ",${opts}," in
          *",${opt},"*) ;;
          *) opts="${opts},${opt}" ;;
        esac
      done
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$src" "$tgt" "$fst" "$opts" "${dump:-0}" "${pass:-0}" >> "$tmp"
    else
      printf '%s\n' "$line" >> "$tmp"
    fi
  done < /etc/fstab
  if [[ "$found" == 0 ]]; then
    rm -f "$tmp"
    return 2
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: would update fstab options for ${mp}: ${want[*]}"
    rm -f "$tmp"
    return 0
  fi
  backup_file /etc/fstab
  cat "$tmp" > /etc/fstab
  rm -f "$tmp"
  return 0
}

ensure_mount_opts() {
  local id="$1" mp="$2"; shift 2
  local current=""
  detail "${id} checking ${mp}. Wanted options: $*"
  if ! is_separate_mount "$mp"; then
    describe_mount "$mp"
    if mount_ignored_when_absent "$mp"; then
      notneeded "${id} ${mp} is not a separate mount. Benchmark item ignored. No partition is created and no options are written."
    else
      manual "${id} ${mp} is not a separate mount. Options not applied. Creating the partition is not automatic."
    fi
    return 0
  fi
  current="$(findmnt -kn -o SOURCE,FSTYPE,OPTIONS --mountpoint "$mp" 2>/dev/null || echo '?')"
  detail "${id} ${mp} is a separate mount: ${current}"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: ${id} would add options on ${mp}: $*"
    ok "${id} ${mp} options (dry-run). Current: ${current}"
    return 0
  fi
  fstab_add_opts "$mp" "$@" || warn "${id} no fstab entry for ${mp}; remounting only this boot"
  if mount -o remount,"$(IFS=,; echo "$*")" "$mp" 2>/dev/null; then
    detail "${id} remounted ${mp} with: $*"
  else
    warn "${id} remount of ${mp} failed; fstab change applies on reboot"
  fi
  current="$(findmnt -kn -o OPTIONS --mountpoint "$mp" 2>/dev/null || echo '?')"
  detail "${id} ${mp} options now: ${current}"
  ok "${id} ${mp} options requested: $*"
}

# Operator rule: these paths are ignored, not created, when they are not
# already an exact mountpoint. /var/log and /dev/shm are not in the list.
mount_ignored_when_absent() {
  case "$1" in
    /tmp|/var/tmp|/home|/var|/var/log/audit) return 0 ;;
    *) return 1 ;;
  esac
}

is_separate_mount() {
  findmnt -kn --mountpoint "$1" >/dev/null 2>&1
}

describe_mount() {
  local mp="$1" own="" parent=""
  own="$(findmnt -kn -o SOURCE,FSTYPE,OPTIONS,TARGET --mountpoint "$mp" 2>/dev/null || true)"
  if [[ -n "$own" ]]; then
    detail "${mp} kernel mountpoint: ${own}"
    return 0
  fi
  parent="$(findmnt -kn -o SOURCE,FSTYPE,TARGET -T "$mp" 2>/dev/null || true)"
  if [[ -n "$parent" ]]; then
    detail "${mp} is not its own mount. It sits on: ${parent}"
  else
    detail "${mp} is not a mountpoint and findmnt -T returned nothing (path may be missing)"
  fi
  if [[ -d "$mp" ]]; then
    detail "${mp} exists as a directory: $(stat -c '%A %U:%G inode=%i' "$mp" 2>/dev/null || echo 'stat failed')"
  elif [[ -e "$mp" ]]; then
    detail "${mp} exists but is not a directory: $(stat -c '%A %F' "$mp" 2>/dev/null || echo 'stat failed')"
  else
    detail "${mp} does not exist"
  fi
  return 1
}

report_separate_mount() {
  local id="$1" mp="$2"
  detail "${id} existence check for separate mount ${mp}"
  if is_separate_mount "$mp"; then
    describe_mount "$mp" || true
    ok "${id} ${mp} is a separate mount"
    return 0
  fi
  describe_mount "$mp" || true
  if mount_ignored_when_absent "$mp"; then
    notneeded "${id} ${mp} is not a separate mount. Partition creation is not performed. Marked not needed."
  else
    manual "${id} ${mp} separate partition is not created. Do this from install media if the site requires it."
  fi
}

append_fstab() {
  local line="$1"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: append fstab: ${line}"
    return 0
  fi
  backup_file /etc/fstab
  printf '%s\n' "$line" >> /etc/fstab
}

service_not_in_use() {
  local id="$1" action="$2" pkg="$3"
  shift 3
  local -a units=("$@")
  local u
  if [[ "$action" == skip ]]; then
    skip "${id} ${pkg} left installed because ${pkg%%-*} action is skip"
    return 0
  fi
  if ! pkg_installed "$pkg"; then
    ok "${id} ${pkg} is not installed"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: ${id} ${action} ${pkg} units: ${units[*]}"
    ok "${id} ${pkg} ${action} (dry-run)"
    return 0
  fi
  for u in "${units[@]}"; do
    run_cmd systemctl stop "$u" || true
  done
  if [[ "$action" == purge && "$PURGE_UNUSED" == 1 ]]; then
    if apt_purge "$pkg"; then
      ok "${id} purged ${pkg}"
      return 0
    fi
    warn "${id} purge of ${pkg} failed; masking units instead"
  fi
  for u in "${units[@]}"; do
    run_cmd systemctl disable "$u" || true
    run_cmd systemctl mask "$u" || true
  done
  ok "${id} ${pkg} units masked: ${units[*]}"
}

client_not_installed() {
  local id="$1"; shift
  local pkg missing=0
  for pkg in "$@"; do
    if pkg_installed "$pkg"; then
      if [[ "$DRY_RUN" == 1 ]]; then
        log "DRY-RUN: ${id} apt purge ${pkg}"
      else
        apt_purge "$pkg" || fail "${id} purge ${pkg} failed"
      fi
    else
      missing=$((missing + 1))
    fi
  done
  if [[ "$missing" -eq "$#" ]]; then
    ok "${id} none of [$*] are installed"
  else
    ok "${id} client packages purged: $*"
  fi
}

# =============================================================================
# 1.1 Filesystem
# =============================================================================

cis_1_1_1_1() { modprobe_disable "1.1.1.1" "cramfs" "cramfs"; }
cis_1_1_1_2() { modprobe_disable "1.1.1.2" "freevxfs" "freevxfs"; }
cis_1_1_1_3() { modprobe_disable "1.1.1.3" "hfs" "hfs"; }
cis_1_1_1_4() { modprobe_disable "1.1.1.4" "hfsplus" "hfsplus"; }
cis_1_1_1_5() { modprobe_disable "1.1.1.5" "jffs2" "jffs2"; }
cis_1_1_1_6() { modprobe_disable "1.1.1.6" "overlay" "overlay"; warn "1.1.1.6 overlay off breaks containers and some live media"; }
cis_1_1_1_7() { modprobe_disable "1.1.1.7" "squashfs" "squashfs"; warn "1.1.1.7 squashfs off breaks snaps"; }
cis_1_1_1_8() { modprobe_disable "1.1.1.8" "udf" "udf"; }
cis_1_1_1_9() { modprobe_disable "1.1.1.9" "usb-storage" "usb_storage"; warn "1.1.1.9 USB storage will not work"; }

cis_1_1_1_10() {
  if [[ "$APPLY_UNUSED_FS" != 1 ]]; then
    manual "1.1.1.10 not applied. Pass --apply-unused-fs only after reviewing mounted filesystems. Denylisting an in-use module can panic the host."
    return 0
  fi
  local mod
  for mod in ceph cifs exfat ext fat fscache fuse gfs2 nfs_common nfsd smbfs_common; do
    findmnt -Dkerno fstype | awk '{print $1}' | grep -qx "$mod" && continue
    lsmod | awk '{print $1}' | grep -qx "$mod" && continue
    modprobe_disable "1.1.1.10" "$mod" "$mod" || true
  done
  ok "1.1.1.10 unused named filesystem modules denylisted where not mounted or loaded"
}

cis_1_1_2_1_1() {
  detail "1.1.2.1.1 does not create a tmpfs /tmp and does not unmask tmp.mount."
  ensure_mount_opts "1.1.2.1.1" /tmp rw nosuid nodev noexec relatime
}
cis_1_1_2_1_2() { ensure_mount_opts "1.1.2.1.2" /tmp nodev; }
cis_1_1_2_1_3() { ensure_mount_opts "1.1.2.1.3" /tmp nosuid; }
cis_1_1_2_1_4() {
  ensure_mount_opts "1.1.2.1.4" /tmp noexec
  if is_separate_mount /tmp; then
    warn "1.1.2.1.4 noexec on /tmp can break installers that execute files from /tmp"
  else
    detail "1.1.2.1.4 noexec warning skipped because /tmp is not a separate mount"
  fi
}
cis_1_1_2_2_1() {
  detail "1.1.2.2.1 /dev/shm is not in the not-needed list. A missing fstab line is added, then options are applied when it is already a mount."
  if ! awk '$2=="/dev/shm"{found=1} END{exit !found}' /etc/fstab 2>/dev/null; then
    detail "1.1.2.2.1 no fstab entry for /dev/shm. Adding tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=${SHM_SIZE}."
    append_fstab "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=${SHM_SIZE} 0 0"
  else
    detail "1.1.2.2.1 /dev/shm already has an fstab line"
  fi
  ensure_mount_opts "1.1.2.2.1" /dev/shm rw nosuid nodev noexec relatime
}
cis_1_1_2_2_2() { ensure_mount_opts "1.1.2.2.2" /dev/shm nodev; }
cis_1_1_2_2_3() { ensure_mount_opts "1.1.2.2.3" /dev/shm nosuid; }
cis_1_1_2_2_4() {
  ensure_mount_opts "1.1.2.2.4" /dev/shm noexec
  if is_separate_mount /dev/shm; then
    warn "1.1.2.2.4 noexec on /dev/shm breaks some browsers and Electron apps"
  fi
}
cis_1_1_2_3_1() { report_separate_mount "1.1.2.3.1" /home; }
cis_1_1_2_3_2() { ensure_mount_opts "1.1.2.3.2" /home nodev; }
cis_1_1_2_3_3() { ensure_mount_opts "1.1.2.3.3" /home nosuid; }
cis_1_1_2_4_1() { report_separate_mount "1.1.2.4.1" /var; }
cis_1_1_2_4_2() { ensure_mount_opts "1.1.2.4.2" /var nodev; }
cis_1_1_2_4_3() { ensure_mount_opts "1.1.2.4.3" /var nosuid; }
cis_1_1_2_5_1() { report_separate_mount "1.1.2.5.1" /var/tmp; }
cis_1_1_2_5_2() { ensure_mount_opts "1.1.2.5.2" /var/tmp nodev; }
cis_1_1_2_5_3() { ensure_mount_opts "1.1.2.5.3" /var/tmp nosuid; }
cis_1_1_2_5_4() { ensure_mount_opts "1.1.2.5.4" /var/tmp noexec; }
cis_1_1_2_6_1() { report_separate_mount "1.1.2.6.1" /var/log; }
cis_1_1_2_6_2() { ensure_mount_opts "1.1.2.6.2" /var/log nodev; }
cis_1_1_2_6_3() { ensure_mount_opts "1.1.2.6.3" /var/log nosuid; }
cis_1_1_2_6_4() { ensure_mount_opts "1.1.2.6.4" /var/log noexec; }
cis_1_1_2_7_1() { report_separate_mount "1.1.2.7.1" /var/log/audit; }
cis_1_1_2_7_2() { ensure_mount_opts "1.1.2.7.2" /var/log/audit nodev; }
cis_1_1_2_7_3() { ensure_mount_opts "1.1.2.7.3" /var/log/audit nosuid; }
cis_1_1_2_7_4() { ensure_mount_opts "1.1.2.7.4" /var/log/audit noexec; }

# =============================================================================
# 1.2 Package management
# =============================================================================

cis_1_2_1_1() {
  emit INFO "GPG key files (review; this script does not delete keys):"
  local f
  shopt -s nullglob
  for f in /etc/apt/trusted.gpg.d/* /etc/apt/sources.list.d/*; do
    emit DETAIL "  key-or-source: ${f}"
  done
  shopt -u nullglob
  manual "1.2.1.1 GPG keys are site policy. Compare the list above with what you expect. Prefer Signed-By in sources."
}

cis_1_2_1_2() {
  local f line nullglob_was=0
  local -i REPO_ENABLED=0 REPO_OFFICIAL=0 REPO_BAD=0 REPO_DISABLED=0
  local -a files=()
  detail "1.2.1.2 allow-list hosts: packages.linuxmint.com *.linuxmint.com archive.ubuntu.com *.archive.ubuntu.com security.ubuntu.com ports.ubuntu.com archive.canonical.com esm.ubuntu.com *.esm.ubuntu.com"
  detail "1.2.1.2 standard suites: Mint wilma, xia, zara, zena (22 through 22.3, all on Ubuntu noble); Ubuntu noble, noble-updates, noble-security, noble-backports"
  detail "1.2.1.2 non-official enabled sources are reported and left installed. This control does not delete or rewrite apt sources."
  shopt -q nullglob && nullglob_was=1
  shopt -s nullglob
  [[ -f /etc/apt/sources.list ]] && files+=("/etc/apt/sources.list")
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    files+=("$f")
  done
  [[ "$nullglob_was" == 1 ]] || shopt -u nullglob
  if ((${#files[@]} == 0)); then
    fail "1.2.1.2 no apt source files under /etc/apt/sources.list or sources.list.d. Nothing was deleted."
    return 0
  fi
  detail "1.2.1.2 scanning ${#files[@]} source file(s)"
  for f in "${files[@]}"; do
    detail "1.2.1.2 reading ${f} ($(wc -c < "$f" | tr -d ' ') bytes)"
    case "$f" in
      *.sources) repo_parse_deb822_file "$f" ;;
      *) repo_parse_oneline_file "$f" ;;
    esac
  done
  detail "1.2.1.2 apt-cache policy follows (informational; the verdict is the per-entry scan above)"
  if command -v apt-cache >/dev/null 2>&1; then
    apt-cache policy 2>/dev/null | while IFS= read -r line; do emit DETAIL "policy: ${line}"; done || warn "1.2.1.2 apt-cache policy failed"
  else
    detail "1.2.1.2 apt-cache is not installed; policy dump skipped"
  fi
  detail "1.2.1.2 summary enabled=${REPO_ENABLED} official=${REPO_OFFICIAL} non_official=${REPO_BAD} disabled_ignored=${REPO_DISABLED}"
  if (( REPO_ENABLED == 0 )); then
    fail "1.2.1.2 no enabled apt entries were found. Nothing was deleted."
  elif (( REPO_BAD > 0 )); then
    fail "1.2.1.2 ${REPO_BAD} enabled entries are not standard Linux Mint 22 or Ubuntu noble repositories (${REPO_OFFICIAL} official of ${REPO_ENABLED} enabled). Sources were NOT removed."
  else
    ok "1.2.1.2 all ${REPO_ENABLED} enabled sources are standard Mint 22 or Ubuntu noble archives. Nothing was rewritten."
  fi
}

repo_host_of() {
  local uri="$1" h
  h="${uri#*://}"
  h="${h%%/*}"
  h="${h%%:*}"
  h="${h,,}"
  printf '%s' "$h"
}

repo_official_host() {
  local h="$1"
  case "$h" in
    packages.linuxmint.com|*.linuxmint.com) return 0 ;;
    archive.ubuntu.com|*.archive.ubuntu.com) return 0 ;;
    security.ubuntu.com|ports.ubuntu.com) return 0 ;;
    archive.canonical.com) return 0 ;;
    esm.ubuntu.com|*.esm.ubuntu.com) return 0 ;;
    *) return 1 ;;
  esac
}

repo_standard_suite() {
  local host="$1" suite="${2,,}"
  case "$host" in
    *linuxmint.com)
      case "$suite" in
        wilma|xia|zara|zena) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    *)
      case "$suite" in
        noble|noble-updates|noble-security|noble-backports) return 0 ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

repo_judge() {
  local file="$1" line_no="$2" enabled="$3" rtype="$4" uri="$5" suite="$6" comps="$7" signedby="$8" fmt="$9"
  local host transport verdict reason
  host="$(repo_host_of "$uri")"
  case "$uri" in
    https:*|mirror+https:*) transport=https ;;
    http:*|mirror+http:*) transport=http ;;
    cdrom:*) transport=cdrom; host="cdrom" ;;
    file:*) transport=file ;;
    *) transport=other ;;
  esac
  if [[ "$signedby" == -----BEGIN* ]]; then
    signedby="<inline-armored-key>"
  fi
  if [[ "$enabled" != 1 ]]; then
    REPO_DISABLED+=1
    detail "repo disabled file=${file} line=${line_no} format=${fmt} type=${rtype} uri=${uri} host=${host} suite=${suite} components=${comps:-<none>} transport=${transport} signed-by=${signedby:-<distro-keyring>} verdict=IGNORED reason=commented-or-Enabled-no"
    return 0
  fi
  REPO_ENABLED+=1
  if [[ "$transport" == cdrom || "$transport" == file || "$transport" == other ]]; then
    verdict=NON-OFFICIAL
    reason="not an official Mint or Ubuntu network archive (transport=${transport})"
  elif repo_official_host "$host"; then
    if repo_standard_suite "$host" "$suite"; then
      verdict=OFFICIAL
      if [[ "$transport" == http ]]; then
        reason="standard suite on an official archive. HTTP is the Mint/Ubuntu default; apt checks InRelease signatures"
      else
        reason="standard suite on an official archive over HTTPS"
      fi
      if [[ -z "$signedby" ]]; then
        reason+="; no per-repo Signed-By, so the distro archive keyring is used"
      else
        reason+="; Signed-By=${signedby}"
      fi
    else
      verdict=NON-OFFICIAL
      reason="official host but suite '${suite}' is not a standard Mint 22 suite (wilma xia zara zena) or Ubuntu noble suite (noble noble-updates noble-security noble-backports)"
    fi
  else
    verdict=NON-OFFICIAL
    reason="host is not an official Mint or Ubuntu archive"
    if [[ "$transport" == http ]]; then
      reason+="; transport is also plain HTTP"
    fi
  fi
  detail "repo enabled file=${file} line=${line_no} format=${fmt} type=${rtype} uri=${uri} host=${host} suite=${suite} components=${comps:-<none>} transport=${transport} signed-by=${signedby:-<distro-keyring>} verdict=${verdict} reason=${reason}"
  if [[ "$verdict" == OFFICIAL ]]; then
    REPO_OFFICIAL+=1
  else
    REPO_BAD+=1
    warn "1.2.1.2 leaving non-official source in place: ${uri} ${suite} (${file}:${line_no})"
  fi
}

repo_parse_oneline_file() {
  local file="$1" lineno=0 line trimmed rest type opts uri suite comps signedby tok enabled
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -z "$trimmed" ]] && continue
    enabled=1
    while [[ "$trimmed" == \#* ]]; do
      enabled=0
      trimmed="${trimmed#\#}"
      trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
    done
    [[ "$trimmed" == deb\ * || "$trimmed" == deb-src\ * ]] || continue
    read -r type rest <<<"$trimmed"
    opts=""
    signedby=""
    if [[ "$rest" == \[* ]]; then
      opts="${rest#\[}"
      opts="${opts%%\]*}"
      rest="${rest#*\]}"
      rest="${rest#"${rest%%[![:space:]]*}"}"
      for tok in $opts; do
        case "$tok" in
          signed-by=*|Signed-By=*) signedby="${tok#*=}" ;;
        esac
      done
    fi
    uri=""
    suite=""
    comps=""
    read -r uri suite comps <<<"$rest"
    repo_judge "$file" "$lineno" "$enabled" "$type" "${uri:-}" "${suite:-}" "${comps:-}" "$signedby" "one-line"
  done < "$file"
}

repo_flush_deb822() {
  local file="$1" start="$2" enabled_word="$3" types="$4" uris="$5" suites="$6" comps="$7" signedby="$8"
  local en=1 t u s
  [[ -n "${types}${uris}${suites}" ]] || return 0
  if [[ -z "$types" || -z "$uris" || -z "$suites" ]]; then
    warn "1.2.1.2 incomplete deb822 stanza in ${file} near line ${start} (types='${types}' uris='${uris}' suites='${suites}'). Counted as non-official and left in place."
    REPO_ENABLED+=1
    REPO_BAD+=1
    return 0
  fi
  [[ "${enabled_word,,}" == "no" ]] && en=0
  for t in $types; do
    for u in $uris; do
      for s in $suites; do
        repo_judge "$file" "$start" "$en" "$t" "$u" "$s" "$comps" "$signedby" "deb822"
      done
    done
  done
}

repo_parse_deb822_file() {
  local file="$1" lineno=0 line key val
  local types="" uris="" suites="" comps="" signedby="" enabled="yes" start=0 cur=""
  [[ -f "$file" ]] || return 0
  repo_deb822_flush() {
    repo_flush_deb822 "$file" "$start" "$enabled" "$types" "$uris" "$suites" "$comps" "$signedby"
    types=""
    uris=""
    suites=""
    comps=""
    signedby=""
    enabled="yes"
    cur=""
    start=0
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      repo_deb822_flush
      continue
    fi
    if [[ "$line" =~ ^[[:space:]] ]]; then
      val="${line#"${line%%[![:space:]]*}"}"
      case "$cur" in
        types) types+=" ${val}" ;;
        uris) uris+=" ${val}" ;;
        suites) suites+=" ${val}" ;;
        components) comps+=" ${val}" ;;
        signed-by) signedby+="${val}" ;;
        enabled) enabled+="${val}" ;;
      esac
      continue
    fi
    [[ "$line" == \#* ]] && continue
    [[ "$line" == *:* ]] || continue
    key="${line%%:*}"
    val="${line#*:}"
    val="${val#"${val%%[![:space:]]*}"}"
    key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
    case "$key" in
      types|uris|suites|components|signed-by|enabled)
        if [[ "$key" == types && -n "$types" ]]; then
          repo_deb822_flush
        fi
        [[ "$start" -eq 0 ]] && start=$lineno
        cur="$key"
        case "$key" in
          types) types="$val" ;;
          uris) uris="$val" ;;
          suites) suites="$val" ;;
          components) comps="$val" ;;
          signed-by) signedby="$val" ;;
          enabled) enabled="$val" ;;
        esac
        ;;
      *) cur="" ;;
    esac
  done < "$file"
  repo_deb822_flush
}

cis_1_2_2_1() {
  local tmp="" rc=0 line="" summary=""
  detail "1.2.2.1 runs apt-get update, then apt-get upgrade. dist-upgrade is never used. --no-apply-updates skips the upgrade. --no-apt-update skips the index refresh."
  if [[ "$APPLY_UPDATES" != 1 ]]; then
    manual "1.2.2.1 apt-get upgrade skipped because --no-apply-updates (or APPLY_UPDATES=0) was set."
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    if [[ "$APT_UPDATE" == 1 ]]; then
      emit DRY-RUN "would run: apt-get update"
    else
      detail "1.2.2.1 apt-get update skipped because --no-apt-update is set"
    fi
    emit DRY-RUN "would run: apt-get upgrade"
    ok "1.2.2.1 apt-get update and apt-get upgrade (dry-run)"
    return 0
  fi
  if [[ "$APT_UPDATE" == 1 ]]; then
    apt_update_once
  else
    detail "1.2.2.1 apt-get update skipped because --no-apt-update is set. Upgrade uses the current index."
  fi
  emit EXEC "running: apt-get upgrade"
  tmp="$(mktemp)"
  set +e
  env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" upgrade >"$tmp" 2>&1
  rc=$?
  set +e
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$rc" -eq 0 ]]; then emit DETAIL "  | ${line}"; else emit ERROR "  | ${line}"; fi
    [[ "$line" =~ ^[0-9]+\ upgraded,[0-9]+\ newly\ installed ]] && summary="$line"
  done < "$tmp"
  rm -f "$tmp"
  detail "1.2.2.1 upgrade summary: ${summary:-no apt summary line}"
  if [[ "$rc" -eq 0 ]]; then
    emit OK "command succeeded (exit 0): apt-get upgrade"
    ok "1.2.2.1 apt-get update and apt-get upgrade finished"
    if [[ -n "$summary" && "$summary" != 0\ upgraded,* ]]; then
      note_reboot "apt-get upgrade installed packages (${summary}). Reboot if a kernel, libc, or systemd was included."
    else
      detail "1.2.2.1 no packages were upgraded"
    fi
  else
    N_CMD_FAIL+=1
    fail "1.2.2.1 apt-get upgrade failed (exit ${rc})"
  fi
}

cis_1_2_2_2() {
  if ! command -v mintupdate-automation >/dev/null 2>&1; then
    fail "1.2.2.2 mintupdate-automation is not installed"
    return 0
  fi
  if run_cmd mintupdate-automation upgrade enable; then
    ok "1.2.2.2 mintupdate-automation-upgrade.timer enabled"
  else
    fail "1.2.2.2 mintupdate-automation upgrade enable failed"
  fi
}

# =============================================================================
# 1.3 AppArmor
# =============================================================================

cis_1_3_1_1() {
  if apt_install apparmor apparmor-utils; then
    ok "1.3.1.1 apparmor and apparmor-utils installed"
  else
    fail "1.3.1.1 apt install apparmor apparmor-utils failed"
  fi
}

grub_add() {
  local token="$1" t have=0
  for t in "${GRUB_ADDITIONS[@]:-}"; do
    [[ "$t" == "$token" ]] && have=1
  done
  [[ "$have" == 0 ]] && GRUB_ADDITIONS+=("$token")
  GRUB_DIRTY=1
}

cis_1_3_1_2() {
  grub_add "apparmor=1"
  grub_add "security=apparmor"
  ok "1.3.1.2 apparmor=1 security=apparmor staged for GRUB_CMDLINE_LINUX. update-grub runs once at the end."
}

cis_1_3_1_4() {
  if [[ ! -d /etc/apparmor.d ]]; then
    fail "1.3.1.4 /etc/apparmor.d is missing"
    return 0
  fi
  if run_cmd aa-enforce /etc/apparmor.d/*; then
    ok "1.3.1.4 aa-enforce /etc/apparmor.d/*"
    [[ "$DRY_RUN" == 1 ]] || note_reboot "AppArmor profiles were set to enforce. Reboot so every daemon starts confined."
  else
    fail "1.3.1.4 aa-enforce failed"
  fi
  if command -v apparmor_status >/dev/null 2>&1 && [[ "$DRY_RUN" != 1 ]]; then
    while IFS= read -r line; do emit DETAIL "apparmor_status: ${line}"; done < <(apparmor_status 2>&1 || true)
  fi
  manual "1.3.1.4 processes that are unconfined but have a profile need that profile loaded and the process restarted."
}
cis_1_3_1_3() { cis_1_3_1_4; }

finalize_grub() {
  [[ "$GRUB_DIRTY" == 1 ]] || return 0
  local file="/etc/default/grub" current="" token
  if [[ -f "$file" ]]; then
    current="$(awk -F= '/^[[:space:]]*GRUB_CMDLINE_LINUX=/{v=$2; gsub(/^"|"$/, "", v); print v; exit}' "$file")"
  fi
  if ((${#GRUB_ADDITIONS[@]})); then
    for token in "${GRUB_ADDITIONS[@]}"; do
      case " ${current} " in
        *" ${token} "*) ;;
        *) current="${current} ${token}" ;;
      esac
    done
  fi
  current="${current# }"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: GRUB_CMDLINE_LINUX=\"${current}\" && update-grub"
    return 0
  fi
  [[ -f "$file" ]] || touch "$file"
  backup_file "$file"
  if grep -Eq '^[[:space:]]*GRUB_CMDLINE_LINUX=' "$file"; then
    sed -ri "s|^[[:space:]]*GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${current}\"|" "$file"
  else
    printf '\nGRUB_CMDLINE_LINUX="%s"\n' "$current" >> "$file"
  fi
  log "applying GRUB_CMDLINE_LINUX=\"${current}\""
  if run_cmd update-grub; then
    note_reboot "GRUB cmdline was updated (apparmor=1 security=apparmor, and audit=1 on Level 2). The running kernel does not pick this up until reboot."
  else
    fail "update-grub failed"
    return 0
  fi
  if [[ -f /boot/grub/grub.cfg ]]; then
    chown root:root /boot/grub/grub.cfg || true
    chmod u-x,go-rwx /boot/grub/grub.cfg || true
  fi
}

cis_1_4_1() {
  if [[ -z "$GRUB_SUPERUSER" || -z "$GRUB_PBKDF2_HASH" ]]; then
    manual "1.4.1 skipped. Set GRUB_SUPERUSER and GRUB_PBKDF2_HASH from: grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64. A bad password needs live media to recover."
    return 0
  fi
  case "$GRUB_SUPERUSER" in
    *[!A-Za-z0-9._-]*) fail "1.4.1 GRUB_SUPERUSER has characters this script will not quote"; return 0 ;;
  esac
  if [[ "$DRY_RUN" != 1 ]]; then
    local tmp
    tmp="$(mktemp)"
    {
      printf '%s\n' '#!/bin/sh'
      printf '%s\n' '# 1.4.1 CIS superuser. Do not put this in 00_header.'
      printf '%s\n' "cat <<'CIS_EOF'"
      printf 'set superusers="%s"\n' "$GRUB_SUPERUSER"
      printf 'password_pbkdf2 %s %s\n' "$GRUB_SUPERUSER" "$GRUB_PBKDF2_HASH"
      printf '%s\n' 'CIS_EOF'
    } > "$tmp"
    backup_file /etc/grub.d/01_cis_superuser
    install -m 0755 -o root -g root "$tmp" /etc/grub.d/01_cis_superuser
    rm -f "$tmp"
  else
    log "DRY-RUN: write /etc/grub.d/01_cis_superuser for ${GRUB_SUPERUSER}"
  fi
  if [[ "$GRUB_UNRESTRICTED" == 1 && -f /etc/grub.d/10_linux ]]; then
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: add --unrestricted to CLASS in /etc/grub.d/10_linux"
    else
      backup_file /etc/grub.d/10_linux
      if grep -q -- '--unrestricted' /etc/grub.d/10_linux; then
        log "1.4.1 --unrestricted already present"
      elif grep -Eq '^CLASS="--class gnu-linux --class gnu --class os"' /etc/grub.d/10_linux; then
        sed -i 's/^CLASS="--class gnu-linux --class gnu --class os"/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux
      else
        manual "1.4.1 could not find the stock CLASS= line in 10_linux. Add --unrestricted yourself if unattended boot is required."
      fi
    fi
  fi
  GRUB_DIRTY=1
  ok "1.4.1 superuser script staged. update-grub runs at the end."
}

cis_1_4_2() {
  if [[ ! -f /boot/grub/grub.cfg ]]; then
    manual "1.4.2 /boot/grub/grub.cfg does not exist. Set the equivalent bootloader file to mode 0600 root:root."
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: chmod u-x,go-rwx /boot/grub/grub.cfg"
    ok "1.4.2 (dry-run)"
    return 0
  fi
  chown root:root /boot/grub/grub.cfg
  chmod u-x,go-rwx /boot/grub/grub.cfg
  ok "1.4.2 /boot/grub/grub.cfg is $(stat -c '%a %U:%G' /boot/grub/grub.cfg)"
}

# =============================================================================
# 1.5 Process hardening
# =============================================================================

SYSCTL_KERNEL=/etc/sysctl.d/60-kernel_sysctl.conf

cis_1_5_1() { sysctl_set kernel.randomize_va_space 2 "$SYSCTL_KERNEL"; ok "1.5.1 kernel.randomize_va_space = 2"; }
cis_1_5_2() {
  sysctl_set kernel.yama.ptrace_scope 1 "$SYSCTL_KERNEL"
  warn "1.5.2 ptrace_scope=1 blocks gdb/strace for non-root. Value 3 is not used; it cannot be undone without a reboot."
  ok "1.5.2 kernel.yama.ptrace_scope = 1"
}
cis_1_5_3() { sysctl_set fs.suid_dumpable 0 "$SYSCTL_KERNEL"; ok "1.5.3 fs.suid_dumpable = 0"; }
cis_1_5_4() {
  if [[ "$DRY_RUN" != 1 ]]; then
    local f
    for f in /etc/security/limits.conf /etc/security/limits.d/*.conf; do
      [[ -f "$f" ]] || continue
      backup_file "$f"
      sed -ri 's/^([^#].*[[:space:]]hard[[:space:]]+core[[:space:]]+[1-9][0-9]*.*)$/# cis-disabled: \1/' "$f" || true
    done
  fi
  write_file /etc/security/limits.d/60-cis-core.conf 644 <<'EOF'
* hard core 0
EOF
  ok "1.5.4 * hard core 0 (next login)"
}
cis_1_5_5() {
  if pkg_installed prelink; then
    run_cmd prelink -ua || true
    apt_purge prelink || fail "1.5.5 could not purge prelink"
  fi
  ok "1.5.5 prelink is not installed"
}
cis_1_5_6() {
  if [[ -f /etc/default/apport ]]; then
    set_kv /etc/default/apport enabled 0 "="
  fi
  if [[ "$DRY_RUN" != 1 ]]; then
    systemctl stop apport.service 2>/dev/null || true
    systemctl mask apport.service 2>/dev/null || true
  fi
  ok "1.5.6 apport enabled=0 and apport.service masked"
}

# =============================================================================
# 1.6 Banners
# =============================================================================

banner_strip_file() {
  local file="$1" id="$2"
  if [[ ! -e "$file" ]]; then
    ok "${id} ${file} absent"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: rewrite ${file} without OS tokens"
  else
    backup_file "$file"
    sed -ri 's/\\[mrsv]//g' "$file" || true
  fi
  write_file "$file" 644 <<EOF
${BANNER_TEXT}
EOF
  chown root:root "$file" 2>/dev/null || true
  chmod u-x,go-wx "$file" 2>/dev/null || true
  ok "${id} ${file} set to site banner, mode 0644 root:root"
}

cis_1_6_1() {
  banner_strip_file /etc/motd "1.6.1"
  local f
  shopt -s nullglob
  for f in /etc/motd.d/*; do
    [[ "$DRY_RUN" == 1 ]] || sed -ri 's/\\[mrsv]//g' "$f" || true
    emit DETAIL "reviewed ${f}"
  done
  shopt -u nullglob
}
cis_1_6_2() { banner_strip_file /etc/issue "1.6.2"; }
cis_1_6_3() { banner_strip_file /etc/issue.net "1.6.3"; }
banner_perms() {
  local file="$1" id="$2"
  if [[ ! -e "$file" ]]; then
    ok "${id} ${file} absent (pass)"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "${id} perms (dry-run)"
    return 0
  fi
  chown root:root "$file"
  chmod u-x,go-wx "$file"
  ok "${id} $(stat -c '%a %U:%G %n' "$file")"
}
cis_1_6_4() { banner_perms /etc/motd "1.6.4"; }
cis_1_6_5() { banner_perms /etc/issue "1.6.5"; }
cis_1_6_6() { banner_perms /etc/issue.net "1.6.6"; }

# =============================================================================
# 1.7 Cinnamon
# =============================================================================

cinnamon_dconf_prepare() {
  mkdir -p /etc/dconf/db/local.d/locks /etc/dconf/profile
  if [[ ! -f /etc/dconf/profile/user ]] || ! grep -q 'system-db:local' /etc/dconf/profile/user 2>/dev/null; then
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: ensure /etc/dconf/profile/user contains system-db:local"
      return 0
    fi
    if [[ ! -f /etc/dconf/profile/user ]]; then
      printf '%s\n' 'user-db:user' 'system-db:local' > /etc/dconf/profile/user
    else
      backup_file /etc/dconf/profile/user
      printf '%s\n' 'system-db:local' >> /etc/dconf/profile/user
    fi
  fi
}

cis_1_7_1() {
  write_file /etc/lightdm/lightdm.conf.d/60-greeter-hide-users.conf 644 <<'EOF'
[Seat:*]
greeter-hide-users=true
EOF
  [[ "$DRY_RUN" == 1 ]] || note_reboot "LightDM greeter-hide-users is read when the display manager starts."
  ok "1.7.1 greeter-hide-users=true"
}

cis_1_7_2() {
  cinnamon_dconf_prepare
  write_file /etc/dconf/db/local.d/60-cis-cinnamon-lock 644 <<'EOF'
[org/cinnamon/desktop/screensaver]
lock-delay=uint32 5

[org/cinnamon/desktop/session]
idle-delay=uint32 900
EOF
  write_file /etc/dconf/db/local.d/locks/60-cis-cinnamon-lock 644 <<'EOF'
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/desktop/session/idle-delay
EOF
  [[ "$DRY_RUN" == 1 ]] || dconf update 2>/dev/null || warn "1.7.2 dconf update failed"
  ok "1.7.2 lock-delay=5 idle-delay=900 via dconf lock. Users must log in again."
}

cis_1_7_3() {
  cinnamon_dconf_prepare
  write_file /etc/dconf/db/local.d/60-cis-cinnamon-media 644 <<'EOF'
[org/cinnamon/desktop/media-handling]
autorun-never=true
EOF
  write_file /etc/dconf/db/local.d/locks/60-cis-cinnamon-media 644 <<'EOF'
/org/cinnamon/desktop/media-handling/autorun-never
EOF
  [[ "$DRY_RUN" == 1 ]] || dconf update 2>/dev/null || true
  ok "1.7.3 autorun-never=true"
}
# =============================================================================
# 2 Services
# =============================================================================

cis_2_1_1() { service_not_in_use "2.1.1" "$AUTOFS_ACTION" autofs autofs.service; }
cis_2_1_2() { service_not_in_use "2.1.2" "$AVAHI_ACTION" avahi-daemon avahi-daemon.socket avahi-daemon.service; }
cis_2_1_3() { service_not_in_use "2.1.3" purge isc-dhcp-server isc-dhcp-server.service isc-dhcp-server6.service; }
cis_2_1_4() { service_not_in_use "2.1.4" purge bind9 named.service; }
cis_2_1_5() { service_not_in_use "2.1.5" purge dnsmasq dnsmasq.service; }
cis_2_1_6() { service_not_in_use "2.1.6" purge vsftpd vsftpd.service; }
cis_2_1_7() { service_not_in_use "2.1.7" purge slapd slapd.service; }
cis_2_1_8() {
  service_not_in_use "2.1.8" purge dovecot-imapd dovecot.socket dovecot.service
  service_not_in_use "2.1.8" purge dovecot-pop3d dovecot.socket dovecot.service
}
cis_2_1_9() { service_not_in_use "2.1.9" purge nfs-kernel-server nfs-server.service; }
cis_2_1_10() { service_not_in_use "2.1.10" purge ypserv ypserv.service; }
cis_2_1_11() { service_not_in_use "2.1.11" "$SSH_ACTION" openssh-server ssh.socket ssh.service; }
cis_2_1_12() { service_not_in_use "2.1.12" "$CUPS_ACTION" cups cups.socket cups.service; }
cis_2_1_13() { service_not_in_use "2.1.13" "$RPCBIND_ACTION" rpcbind rpcbind.socket rpcbind.service; }
cis_2_1_14() { service_not_in_use "2.1.14" "$RSYNC_ACTION" rsync rsync.service; }
cis_2_1_15() { service_not_in_use "2.1.15" purge samba smbd.service; }
cis_2_1_16() { service_not_in_use "2.1.16" purge snmpd snmpd.service; }
cis_2_1_17() { service_not_in_use "2.1.17" purge tftpd-hpa tftpd-hpa.service; }
cis_2_1_18() { service_not_in_use "2.1.18" purge squid squid.service; }
cis_2_1_19() {
  service_not_in_use "2.1.19" purge apache2 apache2.socket apache2.service
  service_not_in_use "2.1.19" purge nginx nginx.service
}
cis_2_1_20() { service_not_in_use "2.1.20" purge xinetd xinetd.service; }
cis_2_1_21() {
  if [[ "$XSERVER_ACTION" != purge ]]; then
    manual "2.1.21 xserver-common was not purged. A Mint desktop needs it. Pass --purge-xserver only on a headless host."
    return 0
  fi
  warn "2.1.21 purging xserver-common removes the graphical desktop"
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "2.1.21 (dry-run purge)"
    return 0
  fi
  apt_purge xserver-common && ok "2.1.21 xserver-common purged" || fail "2.1.21 purge failed"
}

cis_2_1_22() {
  local fixed=0
  if pkg_installed postfix; then
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: postconf -e inet_interfaces=loopback-only"
    else
      postconf -e 'inet_interfaces = loopback-only'
      run_cmd systemctl restart postfix || warn "2.1.22 postfix restart failed"
    fi
    fixed=1
  fi
  if [[ -f /etc/exim4/update-exim4.conf.conf ]]; then
    set_kv /etc/exim4/update-exim4.conf.conf dc_local_interfaces "'127.0.0.1 ; ::1'" "="
    [[ "$DRY_RUN" == 1 ]] || run_cmd update-exim4.conf || true
    fixed=1
  fi
  if [[ "$fixed" == 1 ]]; then
    ok "2.1.22 MTA restricted to loopback where postfix or exim4 is installed"
  else
    ok "2.1.22 no postfix or exim4 installed"
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -lntu 2>/dev/null | awk 'NR>1 && $5 !~ /127[.]0[.]0[.]1/ && $5 !~ /\[::1\]/ && $5 ~ /:(25|465|587)$/ {print}' | while read -r line; do
      manual "2.1.22 non-loopback mail listener: ${line}"
    done
  fi
}

cis_2_1_23() {
  emit INFO "listening sockets (review; nothing is stopped automatically):"
  if command -v ss >/dev/null 2>&1; then
    ss -lntu 2>/dev/null | while IFS= read -r line; do emit DETAIL "listen: ${line}"; done
  fi
  manual "2.1.23 confirm every listener is approved. Stop and mask or purge anything that is not."
}

cis_2_2_1() { client_not_installed "2.2.1" nis; }
cis_2_2_2() { client_not_installed "2.2.2" rsh-redone-client; }
cis_2_2_3() { client_not_installed "2.2.3" talk; }
cis_2_2_4() { client_not_installed "2.2.4" telnet inetutils-telnet; }
cis_2_2_5() {
  if pkg_installed sssd; then
    manual "2.2.5 ldap-utils left installed because sssd is installed. Purging it can break LDAP logins."
    return 0
  fi
  if [[ "$LDAP_UTILS_ACTION" == skip ]]; then
    skip "2.2.5 ldap-utils skipped by LDAP_UTILS_ACTION"
    return 0
  fi
  client_not_installed "2.2.5" ldap-utils
}
cis_2_2_6() { client_not_installed "2.2.6" ftp tnftp; }

select_time_daemon() {
  if [[ "$TIME_SYNC" != auto ]]; then
    printf '%s' "$TIME_SYNC"
    return
  fi
  if systemctl is-active --quiet chrony 2>/dev/null && ! systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    printf '%s' chrony
  else
    printf '%s' timesyncd
  fi
}

cis_2_3_1_1() {
  TIME_DAEMON="$(select_time_daemon)"
  emit INFO "time daemon selected: ${TIME_DAEMON}"
  if [[ "$TIME_DAEMON" == chrony ]]; then
    [[ "$DRY_RUN" == 1 ]] || apt_install chrony || true
    [[ "$DRY_RUN" == 1 ]] || systemctl stop systemd-timesyncd.service 2>/dev/null || true
    [[ "$DRY_RUN" == 1 ]] || systemctl mask systemd-timesyncd.service 2>/dev/null || true
    ok "2.3.1.1 chrony is the single time daemon; timesyncd masked"
  else
    if pkg_installed chrony && [[ "$DRY_RUN" != 1 ]]; then
      apt_purge chrony || warn "2.3.1.1 could not purge chrony"
    fi
    ok "2.3.1.1 systemd-timesyncd is the single time daemon"
  fi
}

cis_2_3_2_1() {
  [[ -z "$TIME_DAEMON" ]] && TIME_DAEMON="$(select_time_daemon)"
  if [[ "$TIME_DAEMON" == chrony ]]; then
    manual "2.3.2.1 skipped because chrony is the selected time daemon. Configure chrony servers in /etc/chrony/chrony.conf."
    return 0
  fi
  write_file /etc/systemd/timesyncd.conf.d/60-timesyncd.conf 644 <<EOF
[Time]
NTP=${NTP_SERVERS}
FallbackNTP=${FALLBACK_NTP}
EOF
  [[ "$DRY_RUN" == 1 ]] || run_cmd systemctl reload-or-restart systemd-timesyncd || true
  ok "2.3.2.1 NTP=${NTP_SERVERS}"
}

cis_2_3_2_2() {
  [[ -z "$TIME_DAEMON" ]] && TIME_DAEMON="$(select_time_daemon)"
  if [[ "$TIME_DAEMON" != timesyncd ]]; then
    [[ "$DRY_RUN" == 1 ]] || systemctl --now mask systemd-timesyncd.service 2>/dev/null || true
    ok "2.3.2.2 timesyncd masked because ${TIME_DAEMON} is in use"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "2.3.2.2 timesyncd enable (dry-run)"
    return 0
  fi
  systemctl unmask systemd-timesyncd.service 2>/dev/null || true
  systemctl --now enable systemd-timesyncd.service && ok "2.3.2.2 systemd-timesyncd enabled" || fail "2.3.2.2 could not enable systemd-timesyncd"
}

cron_installed() { pkg_installed cron || pkg_installed cronie; }

cis_2_4_1_1() {
  if ! cron_installed; then
    skip "2.4.1.1 cron is not installed; section 2.4.1 skipped"
    return 0
  fi
  local unit
  unit="$(systemctl list-unit-files --no-legend 2>/dev/null | awk '$1 ~ /^crond?\.service$/ {print $1; exit}')"
  [[ -n "$unit" ]] || unit="cron.service"
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "2.4.1.1 ${unit} (dry-run)"
    return 0
  fi
  systemctl unmask "$unit" 2>/dev/null || true
  systemctl --now enable "$unit" && ok "2.4.1.1 ${unit} enabled" || fail "2.4.1.1 could not enable ${unit}"
}

perm_path() {
  local id="$1" path="$2" mode="$3"
  if ! cron_installed; then
    skip "${id} cron not installed"
    return 0
  fi
  if [[ ! -e "$path" ]]; then
    manual "${id} ${path} does not exist"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "${id} ${path} (dry-run)"
    return 0
  fi
  chown root:root "$path"
  chmod "$mode" "$path"
  ok "${id} $(stat -c '%a %U:%G %n' "$path")"
}

cis_2_4_1_2() { perm_path "2.4.1.2" /etc/crontab 600; }
cis_2_4_1_3() { perm_path "2.4.1.3" /etc/cron.hourly 700; }
cis_2_4_1_4() { perm_path "2.4.1.4" /etc/cron.daily 700; }
cis_2_4_1_5() { perm_path "2.4.1.5" /etc/cron.weekly 700; }
cis_2_4_1_6() { perm_path "2.4.1.6" /etc/cron.monthly 700; }
cis_2_4_1_7() { perm_path "2.4.1.7" /etc/cron.yearly 700; }
cis_2_4_1_8() { perm_path "2.4.1.8" /etc/cron.d 700; }

cis_2_4_1_9() {
  if ! cron_installed; then
    skip "2.4.1.9 cron not installed"
    return 0
  fi
  local group="root"
  getent group crontab >/dev/null 2>&1 && group="crontab"
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "2.4.1.9 cron.allow root:${group} 640 (dry-run)"
    return 0
  fi
  [[ -e /etc/cron.allow ]] || touch /etc/cron.allow
  chown "root:${group}" /etc/cron.allow
  chmod u-x,g-wx,o-rwx /etc/cron.allow
  if [[ -e /etc/cron.deny ]]; then
    chown "root:${group}" /etc/cron.deny
    chmod u-x,g-wx,o-rwx /etc/cron.deny
  fi
  ok "2.4.1.9 cron.allow is $(stat -c '%a %U:%G' /etc/cron.allow)"
}

cis_2_4_2_1() {
  if ! pkg_installed at; then
    skip "2.4.2.1 at is not installed"
    return 0
  fi
  local group="root"
  getent group daemon >/dev/null 2>&1 && group="daemon"
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "2.4.2.1 at.allow (dry-run)"
    return 0
  fi
  [[ -e /etc/at.allow ]] || touch /etc/at.allow
  chown "root:${group}" /etc/at.allow
  chmod u-x,g-wx,o-rwx /etc/at.allow
  if [[ -e /etc/at.deny ]]; then
    chown "root:${group}" /etc/at.deny
    chmod u-x,g-wx,o-rwx /etc/at.deny
  fi
  ok "2.4.2.1 at.allow is $(stat -c '%a %U:%G' /etc/at.allow)"
}

# =============================================================================
# 3 Network
# =============================================================================

cis_3_1_1() {
  local all="?" def="?" lo="?" mod="?" after_all after_def after_lo
  all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo '?')"
  def="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo '?')"
  lo="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo '?')"
  [[ -r /sys/module/ipv6/parameters/disable ]] && mod="$(cat /sys/module/ipv6/parameters/disable)"
  emit INFO "3.1.1 IPv6 before: all.disable_ipv6=${all} default.disable_ipv6=${def} lo.disable_ipv6=${lo} module.disable=${mod} DISABLE_IPV6=${DISABLE_IPV6}"
  if [[ "$DISABLE_IPV6" == 1 ]]; then
    detail "3.1.1 disabling IPv6 in ${SYSCTL6}: all=1 default=1 lo=1. This is the default. Pass --keep-ipv6 to leave IPv6 up."
    sysctl_set net.ipv6.conf.all.disable_ipv6 1 "$SYSCTL6"
    sysctl_set net.ipv6.conf.default.disable_ipv6 1 "$SYSCTL6"
    sysctl_set net.ipv6.conf.lo.disable_ipv6 1 "$SYSCTL6"
    after_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo '?')"
    after_def="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo '?')"
    after_lo="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo '?')"
    detail "3.1.1 IPv6 after: all.disable_ipv6=${after_all} default.disable_ipv6=${after_def} lo.disable_ipv6=${after_lo}"
    ok "3.1.1 IPv6 disabled (all/default/lo disable_ipv6=1). Addresses already on interfaces stay until reboot or a link reset."
  else
    detail "3.1.1 --keep-ipv6 or DISABLE_IPV6=0. No disable_ipv6 sysctl is written."
    manual "3.1.1 IPv6 left enabled because --keep-ipv6 (or DISABLE_IPV6=0) was set. IPv6 sysctls in 3.3 still apply."
  fi
}

cis_3_1_2() { service_not_in_use "3.1.2" "$BLUETOOTH_ACTION" bluez bluetooth.service; }

cis_3_2_1() { modprobe_disable "3.2.1" "dccp" "dccp"; }
cis_3_2_2() { modprobe_disable "3.2.2" "tipc" "tipc"; }
cis_3_2_3() { modprobe_disable "3.2.3" "rds" "rds"; }
cis_3_2_4() { modprobe_disable "3.2.4" "sctp" "sctp"; }

SYSCTL4=/etc/sysctl.d/60-netipv4_sysctl.conf
SYSCTL6=/etc/sysctl.d/60-netipv6_sysctl.conf

cis_3_3_1() {
  local v4 v6 def6
  v4="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '(unreadable)')"
  v6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '(unreadable)')"
  def6="$(sysctl -n net.ipv6.conf.default.forwarding 2>/dev/null || echo '(unreadable)')"
  detail "3.3.1 forwarding before: net.ipv4.ip_forward=${v4} net.ipv6.conf.all.forwarding=${v6} net.ipv6.conf.default.forwarding=${def6}"
  sysctl_set net.ipv4.ip_forward 0 "$SYSCTL4"
  detail "3.3.1 also persisting IPv6 forwarding=0 on all and default, even if IPv6 is disabled, so turning IPv6 back on later does not enable forwarding."
  sysctl_set net.ipv6.conf.all.forwarding 0 "$SYSCTL6"
  sysctl_set net.ipv6.conf.default.forwarding 0 "$SYSCTL6"
  v4="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '(unreadable)')"
  v6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '(unreadable)')"
  def6="$(sysctl -n net.ipv6.conf.default.forwarding 2>/dev/null || echo '(unreadable)')"
  detail "3.3.1 forwarding after: net.ipv4.ip_forward=${v4} net.ipv6.conf.all.forwarding=${v6} net.ipv6.conf.default.forwarding=${def6}"
  ok "3.3.1 IP forwarding disabled (IPv4 and IPv6)"
}
cis_3_3_2() {
  sysctl_set net.ipv4.conf.all.send_redirects 0 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.send_redirects 0 "$SYSCTL4"
  ok "3.3.2 send_redirects=0"
}
cis_3_3_3() { sysctl_set net.ipv4.icmp_ignore_bogus_error_responses 1 "$SYSCTL4"; ok "3.3.3 icmp_ignore_bogus_error_responses=1"; }
cis_3_3_4() { sysctl_set net.ipv4.icmp_echo_ignore_broadcasts 1 "$SYSCTL4"; ok "3.3.4 icmp_echo_ignore_broadcasts=1"; }
cis_3_3_5() {
  sysctl_set net.ipv4.conf.all.accept_redirects 0 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.accept_redirects 0 "$SYSCTL4"
  detail "3.3.5 persisting IPv6 accept_redirects=0 as well. If IPv6 is already disabled, sysctl -w may fail and the file still holds the value."
  sysctl_set net.ipv6.conf.all.accept_redirects 0 "$SYSCTL6"
  sysctl_set net.ipv6.conf.default.accept_redirects 0 "$SYSCTL6"
  ok "3.3.5 accept_redirects=0"
}
cis_3_3_6() {
  sysctl_set net.ipv4.conf.all.secure_redirects 0 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.secure_redirects 0 "$SYSCTL4"
  ok "3.3.6 secure_redirects=0"
}
cis_3_3_7() {
  sysctl_set net.ipv4.conf.all.rp_filter 1 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.rp_filter 1 "$SYSCTL4"
  ok "3.3.7 rp_filter=1"
}
cis_3_3_8() {
  sysctl_set net.ipv4.conf.all.accept_source_route 0 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.accept_source_route 0 "$SYSCTL4"
  detail "3.3.8 persisting IPv6 accept_source_route=0 as well. If IPv6 is already disabled, sysctl -w may fail and the file still holds the value."
  sysctl_set net.ipv6.conf.all.accept_source_route 0 "$SYSCTL6"
  sysctl_set net.ipv6.conf.default.accept_source_route 0 "$SYSCTL6"
  ok "3.3.8 accept_source_route=0"
}
cis_3_3_9() {
  sysctl_set net.ipv4.conf.all.log_martians 1 "$SYSCTL4"
  sysctl_set net.ipv4.conf.default.log_martians 1 "$SYSCTL4"
  ok "3.3.9 log_martians=1"
}
cis_3_3_10() {
  local before after
  before="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo '(unreadable)')"
  detail "3.3.10 site override: CIS Linux Mint 22 Benchmark v1.0.0 requires net.ipv4.tcp_syncookies=1 (SYN cookies on). This run sets 0 because tcp_syn was requested disabled. A CIS audit of 3.3.10 will fail until this is set back to 1."
  detail "3.3.10 net.ipv4.tcp_syncookies running_before=${before} target=0 file=${SYSCTL4}"
  sysctl_set net.ipv4.tcp_syncookies 0 "$SYSCTL4"
  after="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo '(unreadable)')"
  warn "3.3.10 OVERRIDE net.ipv4.tcp_syncookies ${before} -> ${after} (target 0). CIS wants 1. Nothing else in section 3.3 was inverted."
  ok "3.3.10 tcp_syncookies set to 0 (operator override of CIS, which requires 1)"
}
cis_3_3_11() {
  local all def
  all="$(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null || echo '(unreadable)')"
  def="$(sysctl -n net.ipv6.conf.default.accept_ra 2>/dev/null || echo '(unreadable)')"
  detail "3.3.11 accept_ra before: all=${all} default=${def} ipv6_enabled=$(ipv6_enabled && echo yes || echo no) DISABLE_IPV6=${DISABLE_IPV6}"
  if ! ipv6_enabled; then
    skip "3.3.11 IPv6 is disabled, so router-advertisement sysctls are not applied. Current accept_ra all=${all} default=${def}."
    return 0
  fi
  sysctl_set net.ipv6.conf.all.accept_ra 0 "$SYSCTL6"
  sysctl_set net.ipv6.conf.default.accept_ra 0 "$SYSCTL6"
  ok "3.3.11 accept_ra=0"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: sysctl --system"
    return 0
  fi
  run_cmd sysctl --system || warn "3.3.11 sysctl --system returned non-zero"
  run_cmd sysctl -w net.ipv4.route.flush=1 || true
  run_cmd sysctl -w net.ipv6.route.flush=1 || true
}

# =============================================================================
# 4 Firewall
# =============================================================================

cis_4_1_1() {
  if apt_install gufw; then
    ok "4.1.1 gufw installed"
  else
    fail "4.1.1 apt install gufw failed"
  fi
}
cis_4_1_3() {
  if ! command -v ufw >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: ufw default deny incoming"
      ok "4.1.3 (dry-run, ufw not installed yet)"
      return 0
    fi
    fail "4.1.3 ufw command missing. Install gufw first (4.1.1)."
    return 0
  fi
  run_cmd ufw default deny incoming || fail "4.1.3 ufw default deny incoming failed"
  ok "4.1.3 default deny incoming"
}
cis_4_1_4() {
  if ! command -v ufw >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == 1 ]]; then
      ok "4.1.4 (dry-run, ufw not installed yet)"
      return 0
    fi
    fail "4.1.4 ufw command missing"
    return 0
  fi
  run_cmd ufw default disabled routed || fail "4.1.4 ufw default disabled routed failed"
  run_cmd ufw default allow outgoing || true
  if [[ "$UFW_ALLOW_SSH" == 1 ]]; then
    run_cmd ufw allow OpenSSH || true
    log "4.1.4 added ufw allow OpenSSH because --allow-ssh was set"
  fi
  ok "4.1.4 routed policy is disabled; outgoing allow is not a numbered control"
}
cis_4_1_2() {
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: systemctl enable ufw; ufw --force enable (UFW_ENABLE=${UFW_ENABLE})"
    ok "4.1.2 (dry-run)"
    return 0
  fi
  if ! command -v ufw >/dev/null 2>&1; then
    fail "4.1.2 ufw command missing"
    return 0
  fi
  systemctl unmask ufw.service 2>/dev/null || true
  systemctl --now enable ufw.service || fail "4.1.2 could not enable ufw.service"
  if [[ "$UFW_ENABLE" == 1 ]]; then
    warn "4.1.2 enabling ufw. This flushes firewall chains and can drop SSH."
    run_cmd ufw --force enable || fail "4.1.2 ufw --force enable failed"
    ok "4.1.2 ufw status: $(ufw status 2>/dev/null | head -n 1)"
  else
    manual "4.1.2 ufw.service is enabled but UFW_ENABLE=0 so 'ufw enable' was not run."
  fi
}
# =============================================================================
# 5 Access, PAM, accounts
# =============================================================================

install_sudoers_dropin() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: install /etc/sudoers.d/60-cis-defaults"
    rm -f "$tmp"
    return 0
  fi
  if ! visudo -cf "$tmp"; then
    rm -f "$tmp"
    fail "sudoers drop-in failed visudo -cf"
    return 1
  fi
  backup_file /etc/sudoers.d/60-cis-defaults
  install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/60-cis-defaults
  rm -f "$tmp"
}

cis_sudoers_refresh() {
  local timeout_line=""
  if [[ "${SET_SUDO_TIMEOUT:-0}" == 1 ]]; then
    timeout_line="Defaults timestamp_timeout=15"
  fi
  install_sudoers_dropin <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
${timeout_line}
EOF
}

comment_sudoers_token() {
  local regex="$1" why="$2" f tmp
  shopt -s nullglob
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *~ ]] && continue
    grep -Eq "$regex" "$f" || continue
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: comment ${why} in ${f}"
      continue
    fi
    tmp="$(mktemp)"
    awk -v re="$regex" -v why="$why" '
      /^[[:space:]]*#/ { print; next }
      $0 ~ re { print "# cis-disabled (" why "): " $0; next }
      { print }
    ' "$f" > "$tmp"
    if visudo -cf "$tmp"; then
      backup_file "$f"
      cat "$tmp" > "$f"
      emit INFO "commented ${why} in ${f}"
    else
      fail "visudo rejected edit of ${f} while removing ${why}"
    fi
    rm -f "$tmp"
  done
  shopt -u nullglob
}

cis_5_1_1() {
  if pkg_installed sudo || pkg_installed sudo-ldap; then
    ok "5.1.1 sudo or sudo-ldap already installed"
    return 0
  fi
  apt_install sudo && ok "5.1.1 sudo installed" || fail "5.1.1 apt install sudo failed"
}
cis_5_1_2() {
  comment_sudoers_token '!use_pty' '!use_pty'
  cis_sudoers_refresh || return 0
  ok "5.1.2 Defaults use_pty"
}
cis_5_1_3() {
  cis_sudoers_refresh || return 0
  ok "5.1.3 Defaults logfile=/var/log/sudo.log"
}
cis_5_1_4() {
  comment_sudoers_token 'NOPASSWD' 'NOPASSWD'
  ok "5.1.4 NOPASSWD lines commented. Automated jobs that used them will prompt."
}
cis_5_1_5() {
  comment_sudoers_token '!authenticate' '!authenticate'
  ok "5.1.5 !authenticate removed"
}
cis_5_1_6() {
  local bad=0 line val
  if grep -RIsn --exclude='*~' 'timestamp_timeout' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^[^:]*:[[:space:]]*#' | while read -r line; do
    val="$(printf '%s' "$line" | sed -n 's/.*timestamp_timeout=\(-\?[0-9][0-9]*\).*/\1/p')"
    if [[ -n "$val" ]] && { [[ "$val" == -* ]] || (( val > 15 )); }; then
      printf '%s\n' "$line"
    fi
  done | grep -q .; then
    bad=1
  fi
  if [[ "$bad" == 1 ]]; then
    comment_sudoers_token 'timestamp_timeout' 'timestamp_timeout'
    SET_SUDO_TIMEOUT=1
    cis_sudoers_refresh || true
    ok "5.1.6 noncompliant timestamp_timeout replaced with 15"
  else
    ok "5.1.6 sudo timestamp is already within 0..15 minutes (compiled default is 5 if unset)"
  fi
}
cis_5_1_7() {
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "5.1.7 sugroup + pam_wheel (dry-run)"
    return 0
  fi
  getent group "$SU_GROUP" >/dev/null || groupadd "$SU_GROUP"
  if [[ -n "$(getent group "$SU_GROUP" | awk -F: '{print $4}')" ]]; then
    manual "5.1.7 group ${SU_GROUP} has members. The benchmark wants it empty so nobody can su until you add an admin."
  fi
  local line="auth required pam_wheel.so use_uid group=${SU_GROUP}"
  if grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel.so' /etc/pam.d/su 2>/dev/null; then
    backup_file /etc/pam.d/su
    sed -ri "s|^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel.so.*|${line}|" /etc/pam.d/su
  else
    backup_file /etc/pam.d/su
    printf '%s\n' "$line" >> /etc/pam.d/su
  fi
  ok "5.1.7 su requires group ${SU_GROUP}, which is empty until you add a user"
}

pam_enable() {
  local profile="$1"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: pam-auth-update --force --enable ${profile}"
    return 0
  fi
  local f
  for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    backup_file "$f"
  done
  if DEBIAN_FRONTEND=noninteractive pam-auth-update --force --enable "$profile" </dev/null; then
    note_reboot "PAM stack was rewritten (${profile}). Current sessions keep the old stack until the next login."
  else
    fail "pam-auth-update --enable ${profile} failed"
  fi
}

strip_pam_arg() {
  local arg="$1" f
  shopt -s nullglob
  for f in /usr/share/pam-configs/*; do
    [[ -f "$f" ]] || continue
    grep -q "$arg" "$f" || continue
    [[ "$DRY_RUN" == 1 ]] && { log "DRY-RUN: strip ${arg} from ${f}"; continue; }
    backup_file "$f"
    sed -ri "s/[[:space:]]*${arg}(=[^[:space:]]*)?//g" "$f"
  done
  shopt -u nullglob
}

cis_5_2_1_1() { apt_install libpam-runtime && ok "5.2.1.1 libpam-runtime" || fail "5.2.1.1 libpam-runtime"; }
cis_5_2_1_2() { apt_install libpam-modules && ok "5.2.1.2 libpam-modules" || fail "5.2.1.2 libpam-modules"; }
cis_5_2_1_3() { apt_install libpam-pwquality && ok "5.2.1.3 libpam-pwquality" || fail "5.2.1.3 libpam-pwquality"; }

cis_5_2_2_1() {
  strip_pam_arg nullok
  strip_pam_arg 'remember'
  pam_enable unix
  ok "5.2.2.1 pam_unix enabled, nullok and remember stripped from profiles"
}

cis_5_2_2_2() {
  write_file /usr/share/pam-configs/faillock 644 <<'EOF'
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]			pam_faillock.so authfail
EOF
  write_file /usr/share/pam-configs/faillock_notify 644 <<'EOF'
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite			pam_faillock.so preauth
Account-Type: Primary
Account:
	required			pam_faillock.so
EOF
  pam_enable faillock
  pam_enable faillock_notify
  ok "5.2.2.2 pam_faillock profiles enabled"
}

cis_5_2_2_3() {
  if [[ ! -f /usr/share/pam-configs/pwquality ]]; then
    write_file /usr/share/pam-configs/pwquality 644 <<'EOF'
Name: Pwquality password strength checking
Default: yes
Priority: 1024
Conflicts: cracklib
Password-Type: Primary
Password:
	requisite			pam_pwquality.so retry=3
EOF
  fi
  pam_enable pwquality
  ok "5.2.2.3 pam_pwquality retry=3 enabled"
}

cis_5_2_2_4() {
  write_file /usr/share/pam-configs/pwhistory 644 <<EOF
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
	requisite			pam_pwhistory.so remember=${PW_REMEMBER} enforce_for_root use_authtok
EOF
  pam_enable pwhistory
  ok "5.2.2.4 pam_pwhistory remember=${PW_REMEMBER} enforce_for_root use_authtok"
}

cis_5_2_3_1_1() {
  strip_pam_arg 'deny'
  set_kv /etc/security/faillock.conf deny "$FAILLOCK_DENY"
  ok "5.2.3.1.1 deny = ${FAILLOCK_DENY}"
}
cis_5_2_3_1_2() {
  strip_pam_arg 'unlock_time'
  set_kv /etc/security/faillock.conf unlock_time "$FAILLOCK_UNLOCK_TIME"
  ok "5.2.3.1.2 unlock_time = ${FAILLOCK_UNLOCK_TIME} (900 is the smallest non-zero value the audit accepts; the printed sample of 300 fails that audit)"
}
cis_5_2_3_1_3() {
  strip_pam_arg 'even_deny_root'
  strip_pam_arg 'root_unlock_time'
  if [[ "$DRY_RUN" != 1 ]]; then
    grep -q '^even_deny_root' /etc/security/faillock.conf 2>/dev/null || printf '%s\n' 'even_deny_root' >> /etc/security/faillock.conf
  fi
  set_kv /etc/security/faillock.conf root_unlock_time "$ROOT_UNLOCK_TIME"
  ok "5.2.3.1.3 even_deny_root and root_unlock_time = ${ROOT_UNLOCK_TIME}"
}

comment_pwquality_key() {
  local key="$1" except="$2" f
  shopt -s nullglob
  for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
    [[ -f "$f" && "$f" != "$except" ]] || continue
    [[ "$DRY_RUN" == 1 ]] && continue
    backup_file "$f"
    sed -ri "s/^([[:space:]]*${key}[[:space:]]*=)/# cis-disabled: \\1/" "$f"
  done
  shopt -u nullglob
}

cis_5_2_3_2_1() {
  local f=/etc/security/pwquality.conf.d/50-pwdifok.conf
  comment_pwquality_key difok "$f"
  strip_pam_arg difok
  write_file "$f" 644 <<EOF
difok = ${PW_DIFOK}
EOF
  ok "5.2.3.2.1 difok = ${PW_DIFOK}"
}
cis_5_2_3_2_2() {
  local f=/etc/security/pwquality.conf.d/50-pwlength.conf
  comment_pwquality_key minlen "$f"
  strip_pam_arg minlen
  write_file "$f" 644 <<EOF
minlen = ${PW_MINLEN}
EOF
  ok "5.2.3.2.2 minlen = ${PW_MINLEN}"
}
cis_5_2_3_2_3() {
  if [[ "$APPLY_PWCOMPLEXITY" != 1 ]]; then
    manual "5.2.3.2.3 password complexity is Manual. Pass --pwcomplexity to write minclass = 3."
    return 0
  fi
  local f=/etc/security/pwquality.conf.d/50-pwcomplexity.conf
  comment_pwquality_key minclass "$f"
  write_file "$f" 644 <<'EOF'
minclass = 3
EOF
  ok "5.2.3.2.3 minclass = 3"
}
cis_5_2_3_2_4() {
  local f=/etc/security/pwquality.conf.d/50-pwrepeat.conf
  comment_pwquality_key maxrepeat "$f"
  strip_pam_arg maxrepeat
  write_file "$f" 644 <<EOF
maxrepeat = ${PW_MAXREPEAT}
EOF
  ok "5.2.3.2.4 maxrepeat = ${PW_MAXREPEAT}"
}
cis_5_2_3_2_5() {
  local f=/etc/security/pwquality.conf.d/50-pwmaxsequence.conf
  comment_pwquality_key maxsequence "$f"
  strip_pam_arg maxsequence
  write_file "$f" 644 <<EOF
maxsequence = ${PW_MAXSEQUENCE}
EOF
  ok "5.2.3.2.5 maxsequence = ${PW_MAXSEQUENCE}"
}
cis_5_2_3_2_6() {
  strip_pam_arg dictcheck
  [[ "$DRY_RUN" == 1 ]] || comment_active_key /etc/security/pwquality.conf dictcheck
  shopt -s nullglob
  local f
  for f in /etc/security/pwquality.conf.d/*.conf; do
    [[ "$DRY_RUN" == 1 ]] || comment_active_key "$f" dictcheck
  done
  shopt -u nullglob
  ok "5.2.3.2.6 dictcheck=0 commented so the default of 1 (on) stands"
}
cis_5_2_3_2_7() {
  strip_pam_arg enforcing
  [[ "$DRY_RUN" == 1 ]] || comment_active_key /etc/security/pwquality.conf enforcing
  ok "5.2.3.2.7 enforcing=0 commented so the default of 1 stands"
}
cis_5_2_3_2_8() {
  write_file /etc/security/pwquality.conf.d/50-pwroot.conf 644 <<'EOF'
enforce_for_root
EOF
  ok "5.2.3.2.8 enforce_for_root"
}
cis_5_2_3_3_1() { cis_5_2_2_4; }
cis_5_2_3_3_2() {
  if grep -q 'enforce_for_root' /usr/share/pam-configs/pwhistory 2>/dev/null; then
    ok "5.2.3.3.2 enforce_for_root is on the pwhistory line"
  else
    cis_5_2_2_4
  fi
}
cis_5_2_3_3_3() {
  if grep -q 'use_authtok' /usr/share/pam-configs/pwhistory 2>/dev/null; then
    ok "5.2.3.3.3 use_authtok is on the pwhistory line"
  else
    cis_5_2_2_4
  fi
}
cis_5_2_3_4_1() { strip_pam_arg nullok; pam_enable unix; ok "5.2.3.4.1 nullok removed from pam_unix profiles"; }
cis_5_2_3_4_2() { strip_pam_arg 'remember'; pam_enable unix; ok "5.2.3.4.2 remember removed from pam_unix (history is pam_pwhistory)"; }
cis_5_2_3_4_3() {
  if [[ -f /usr/share/pam-configs/unix ]] && [[ "$DRY_RUN" != 1 ]]; then
    backup_file /usr/share/pam-configs/unix
    if grep -q 'pam_unix.so' /usr/share/pam-configs/unix && ! grep -q 'yescrypt' /usr/share/pam-configs/unix; then
      sed -ri '/pam_unix.so/ s/$/ yescrypt/' /usr/share/pam-configs/unix
    fi
  fi
  pam_enable unix
  if [[ "$EXPIRE_HASHES" == 1 && "$DRY_RUN" != 1 ]]; then
    warn "5.2.3.4.3 expiring password hashes so users must change them (EXPIRE_HASHES=1)"
    awk -F: -v min="$(uid_min)" '($3>=min && $1!="nfsnobody"){print $1}' /etc/passwd | while read -r u; do
      chage -d 0 "$u" || true
    done
  else
    manual "5.2.3.4.3 existing hashes are not expired. Pass --expire-hashes to force a change on next login. New passwords use yescrypt."
  fi
  ok "5.2.3.4.3 pam_unix includes yescrypt"
}
cis_5_2_3_4_4() {
  ok "5.2.3.4.4 use_authtok is on the Password line of the unix profile written by the distribution or by 5.2.2.1. It is not added to Password-Initial."
}

set_login_defs() {
  local key="$1" value="$2"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: ${key} ${value} in /etc/login.defs"
    return 0
  fi
  [[ -f /etc/login.defs ]] || touch /etc/login.defs
  backup_file /etc/login.defs
  if grep -Eq "^[[:space:]]*${key}[[:space:]]+" /etc/login.defs; then
    sed -ri "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" /etc/login.defs
  else
    printf '%s %s\n' "$key" "$value" >> /etc/login.defs
  fi
}

chage_shadow_users() {
  local field="$1" min="$2" max="$3"
  shift 3
  [[ "$DRY_RUN" == 1 ]] && { log "DRY-RUN: chage $* for shadow field ${field} outside ${min}..${max}"; return 0; }
  local user
  while read -r user; do
    [[ -n "$user" ]] || continue
    log "chage $* ${user}"
    chage "$@" "$user" || fail "chage $* ${user} failed"
  done < <(awk -F: -v field="$field" -v min="$min" -v max="$max" '
    $2 ~ /^\$[^$]+\$/ {
      val = $field
      if (val == "") val = -1
      if (val+0 > max || val+0 < min) print $1
    }
  ' /etc/shadow)
}

cis_5_3_1_1() {
  set_login_defs PASS_MAX_DAYS "$PASS_MAX_DAYS"
  chage_shadow_users 5 1 "$PASS_MAX_DAYS" --maxdays "$PASS_MAX_DAYS"
  ok "5.3.1.1 PASS_MAX_DAYS ${PASS_MAX_DAYS}"
}
cis_5_3_1_2() {
  set_login_defs PASS_MIN_DAYS "$PASS_MIN_DAYS"
  chage_shadow_users 4 "$PASS_MIN_DAYS" 99999 --mindays "$PASS_MIN_DAYS"
  ok "5.3.1.2 PASS_MIN_DAYS ${PASS_MIN_DAYS} (benchmark marks this manual; applied because --level2 was set)"
}
cis_5_3_1_3() {
  set_login_defs PASS_WARN_AGE "$PASS_WARN_AGE"
  chage_shadow_users 6 "$PASS_WARN_AGE" 99999 --warndays "$PASS_WARN_AGE"
  ok "5.3.1.3 PASS_WARN_AGE ${PASS_WARN_AGE}"
}
cis_5_3_1_4() {
  set_login_defs ENCRYPT_METHOD YESCRYPT
  ok "5.3.1.4 ENCRYPT_METHOD YESCRYPT (group passwords; user passwords follow PAM)"
}
cis_5_3_1_5() {
  if [[ "$DRY_RUN" != 1 ]]; then
    useradd -D -f "$INACTIVE_DAYS" || fail "5.3.1.5 useradd -D -f ${INACTIVE_DAYS} failed"
  fi
  chage_shadow_users 7 0 "$INACTIVE_DAYS" --inactive "$INACTIVE_DAYS"
  ok "5.3.1.5 INACTIVE=${INACTIVE_DAYS}"
}
cis_5_3_1_6() {
  local today user days
  today="$(( $(date +%s) / 86400 ))"
  while IFS=: read -r user _ _ days _; do
    [[ "$days" =~ ^[0-9]+$ ]] || continue
    if (( days > today )); then
      manual "5.3.1.6 ${user} last password change is in the future (${days} days since epoch). Investigate before chage."
    fi
  done < <(awk -F: '$2 ~ /^\$/ {print $1":"$3}' /etc/shadow)
  ok "5.3.1.6 future last-change dates reported"
}
cis_5_3_2_1() {
  local extra
  extra="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)"
  if [[ -n "$extra" ]]; then
    manual "5.3.2.1 UID 0 is not only root: ${extra}. Reassign those UIDs by hand."
  else
    ok "5.3.2.1 only root has UID 0"
  fi
}
cis_5_3_2_2() {
  local extra
  extra="$(awk -F: '($4==0 && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!="operator"){print $1}' /etc/passwd)"
  if [[ -n "$extra" ]]; then
    manual "5.3.2.2 primary GID 0 is not only root (exempt sync shutdown halt operator): ${extra}"
  else
    ok "5.3.2.2 root is the only unexpected GID 0 account"
  fi
}
cis_5_3_2_3() {
  local extra
  extra="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/group)"
  if [[ -n "$extra" ]]; then
    manual "5.3.2.3 GID 0 groups other than root: ${extra}"
  else
    ok "5.3.2.3 only group root has GID 0"
  fi
}
cis_5_3_2_4() {
  local st
  st="$(passwd -S root 2>/dev/null | awk '{print $2}')"
  case "$st" in
    P|L) ok "5.3.2.4 root password status is ${st}" ;;
    *)
      if [[ "$DRY_RUN" == 1 ]]; then
        log "DRY-RUN: usermod -L root"
      else
        usermod -L root || true
      fi
      ok "5.3.2.4 root locked (previous status ${st:-unknown})"
      ;;
  esac
}
cis_5_3_2_5() {
  local path dir mode owner
  path="$(getent passwd root | awk -F: '{print $7}')"
  path="${PATH}"
  IFS=':' read -r -a parts <<<"$path"
  local p
  for p in "${parts[@]}"; do
    if [[ -z "$p" || "$p" == "." ]]; then
      manual "5.3.2.5 root PATH contains an empty or '.' element: ${path}"
      return 0
    fi
    if [[ ! -d "$p" ]]; then
      manual "5.3.2.5 root PATH element is not a directory: ${p}"
      continue
    fi
    owner="$(stat -c '%U' "$p" 2>/dev/null || echo '?')"
    mode="$(stat -c '%a' "$p" 2>/dev/null || echo 0)"
    if [[ "$owner" != root ]]; then
      manual "5.3.2.5 ${p} is owned by ${owner}"
    fi
    if [[ $((8#$mode & 8#022)) -ne 0 ]]; then
      manual "5.3.2.5 ${p} mode ${mode} is looser than 0755"
    fi
  done
  ok "5.3.2.5 root PATH reviewed"
}
cis_5_3_2_6() {
  local f
  for f in /root/.bashrc /root/.profile; do
    [[ -f "$f" ]] || continue
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: ensure umask 027 in ${f}"
      continue
    fi
    backup_file "$f"
    if grep -Eq '^[[:space:]]*umask[[:space:]]+' "$f"; then
      sed -ri 's/^[[:space:]]*umask[[:space:]]+.*/umask 027/' "$f"
    else
      printf '\n%s\n' 'umask 027' >> "$f"
    fi
  done
  ok "5.3.2.6 root umask 027"
}
cis_5_3_2_7() {
  local nologin min user uid shell base
  nologin="$(command -v nologin || echo /usr/sbin/nologin)"
  min="$(uid_min)"
  [[ "$DRY_RUN" == 1 ]] && { ok "5.3.2.7 (dry-run)"; return 0; }
  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$user" =~ ^(root|halt|sync|shutdown|nfsnobody)$ ]] && continue
    if (( uid < min || uid == 65534 )); then
      base="$(basename "$shell")"
      if [[ "$base" != nologin && "$base" != false ]]; then
        usermod -s "$nologin" "$user" || fail "5.3.2.7 usermod -s nologin ${user} failed"
        emit INFO "5.3.2.7 ${user} shell set to ${nologin}"
      fi
    fi
  done < /etc/passwd
  ok "5.3.2.7 system accounts do not have a login shell"
}
cis_5_3_2_8() {
  local user shell st
  [[ "$DRY_RUN" == 1 ]] && { ok "5.3.2.8 (dry-run)"; return 0; }
  while IFS=: read -r user _ _ _ _ _ shell; do
    [[ "$user" == root ]] && continue
    grep -Fxq "$shell" /etc/shells 2>/dev/null && continue
    st="$(passwd -S "$user" 2>/dev/null | awk '{print $2}')"
    [[ "$st" == L* ]] && continue
    usermod -L "$user" || fail "5.3.2.8 could not lock ${user}"
    emit INFO "5.3.2.8 locked ${user} (shell ${shell} is not a login shell)"
  done < /etc/passwd
  ok "5.3.2.8 accounts without a valid login shell are locked"
}
cis_5_3_3_1() {
  if [[ -f /etc/shells ]]; then
    [[ "$DRY_RUN" == 1 ]] || backup_file /etc/shells
    [[ "$DRY_RUN" == 1 ]] || sed -i '/nologin/d' /etc/shells
  fi
  ok "5.3.3.1 nologin removed from /etc/shells"
}
cis_5_3_3_2() {
  write_file /etc/profile.d/50-tmout.sh 644 <<EOF
# CIS 5.3.3.2. One assignment. readonly and exported.
typeset -xr TMOUT=${TMOUT_SECONDS}
EOF
  if [[ "$DRY_RUN" != 1 ]]; then
    local f
    for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
      [[ -f "$f" && "$f" != /etc/profile.d/50-tmout.sh ]] || continue
      if grep -Eq '^[[:space:]]*(readonly|typeset).*TMOUT|^[[:space:]]*TMOUT=' "$f"; then
        backup_file "$f"
        sed -ri 's/^([[:space:]]*(readonly|typeset).*\bTMOUT\b.*|[[:space:]]*TMOUT=.*)/# cis-disabled: \1/' "$f"
      fi
    done
  fi
  ok "5.3.3.2 TMOUT=${TMOUT_SECONDS}"
}
cis_5_3_3_3() {
  set_login_defs UMASK 027
  write_file /etc/profile.d/60-default_umask.sh 644 <<'EOF'
umask 027
EOF
  ok "5.3.3.3 default umask 027"
}

# =============================================================================
# 6 Logging, audit, AIDE
# =============================================================================

journald_set() {
  local key="$1" value="$2"
  local file=/etc/systemd/journald.conf.d/60-cis-journald.conf
  if [[ "$DRY_RUN" == 1 ]]; then
    log "DRY-RUN: ${key}=${value} in ${file}"
    return 0
  fi
  mkdir -p /etc/systemd/journald.conf.d
  [[ -f "$file" ]] || printf '%s\n' '[Journal]' > "$file"
  grep -q '^\[Journal\]' "$file" || sed -i '1i[Journal]' "$file"
  if grep -Eq "^[[:space:]]*${key}=" "$file"; then
    sed -ri "s|^[[:space:]]*${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
  if [[ -f /etc/systemd/journald.conf ]] && grep -Eq "^[[:space:]]*${key}=" /etc/systemd/journald.conf; then
    backup_file /etc/systemd/journald.conf
    sed -ri "s|^([[:space:]]*${key}=.*)|# cis-disabled: \\1|" /etc/systemd/journald.conf
  fi
}

cis_6_1_1_1() {
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.1.1.1 journald (dry-run)"
    return 0
  fi
  systemctl unmask systemd-journald.service 2>/dev/null || true
  systemctl start systemd-journald.service || fail "6.1.1.1 could not start systemd-journald"
  ok "6.1.1.1 systemd-journald active"
}
cis_6_1_1_2() {
  manual "6.1.1.2 journal file permissions are Manual. Recommended new files are mode 0640 or tighter. Copy /usr/lib/tmpfiles.d/systemd.conf to /etc/tmpfiles.d only if the defaults are wrong."
}
cis_6_1_1_3() {
  if [[ "$APPLY_JOURNAL_ROTATION" != 1 ]]; then
    manual "6.1.1.3 journal rotation is site policy. Pass --journal-rotation to write SystemMaxUse=1G SystemKeepFree=500M RuntimeMaxUse=200M RuntimeKeepFree=50M MaxFileSec=1month."
    return 0
  fi
  write_file /etc/systemd/journald.conf.d/60-journald-rotation.conf 644 <<'EOF'
[Journal]
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
EOF
  [[ "$DRY_RUN" == 1 ]] || systemctl reload-or-restart systemd-journald || true
  ok "6.1.1.3 example rotation values written"
}
cis_6_1_2_1_1() { apt_install systemd-journal-remote && ok "6.1.2.1.1 systemd-journal-remote installed" || fail "6.1.2.1.1 install failed"; }
cis_6_1_2_1_2() {
  if [[ -z "$JOURNAL_UPLOAD_URL" ]]; then
    manual "6.1.2.1.2 set JOURNAL_UPLOAD_URL, JOURNAL_SERVER_KEY, JOURNAL_SERVER_CERT, and JOURNAL_TRUSTED_CERT before enabling upload."
    return 0
  fi
  write_file /etc/systemd/journal-upload.conf.d/60-cis-upload.conf 640 <<EOF
[Upload]
URL=${JOURNAL_UPLOAD_URL}
ServerKeyFile=${JOURNAL_SERVER_KEY}
ServerCertificateFile=${JOURNAL_SERVER_CERT}
TrustedCertificateFile=${JOURNAL_TRUSTED_CERT}
EOF
  ok "6.1.2.1.2 journal upload URL configured"
}
cis_6_1_2_1_3() {
  if [[ -z "$JOURNAL_UPLOAD_URL" ]]; then
    manual "6.1.2.1.3 upload not enabled because JOURNAL_UPLOAD_URL is empty."
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.1.2.1.3 (dry-run)"
    return 0
  fi
  systemctl unmask systemd-journal-upload.service || true
  systemctl --now enable systemd-journal-upload.service && ok "6.1.2.1.3 journal-upload enabled" || fail "6.1.2.1.3 enable failed"
}
cis_6_1_2_1_4() {
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.1.2.1.4 mask journal-remote (dry-run)"
    return 0
  fi
  systemctl stop systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null || true
  systemctl mask systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null || true
  ok "6.1.2.1.4 systemd-journal-remote receiver masked"
}
cis_6_1_2_2() { journald_set ForwardToSyslog no; [[ "$DRY_RUN" == 1 ]] || systemctl reload-or-restart systemd-journald || true; ok "6.1.2.2 ForwardToSyslog=no"; }
cis_6_1_2_3() { journald_set Compress yes; [[ "$DRY_RUN" == 1 ]] || systemctl reload-or-restart systemd-journald || true; ok "6.1.2.3 Compress=yes"; }
cis_6_1_2_4() { journald_set Storage persistent; [[ "$DRY_RUN" == 1 ]] || systemctl reload-or-restart systemd-journald || true; ok "6.1.2.4 Storage=persistent"; }

cis_6_1_3_1() {
  [[ "$DRY_RUN" == 1 ]] && { ok "6.1.3.1 log perms (dry-run)"; return 0; }
  [[ -d /var/log ]] || { manual "6.1.3.1 /var/log missing"; return 0; }
  local f base
  while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    case "$f" in
      /var/log/apt/*) chmod u-x,go-wx "$f" 2>/dev/null || true ;;
      *)
        case "$base" in
          lastlog*|wtmp*|btmp*|README) chmod ug-x,o-wx "$f" 2>/dev/null || true ;;
          auth.log*|syslog*|secure|messages) chmod u-x,g-wx,o-rwx "$f" 2>/dev/null || true ;;
          *.journal|*.journal~) chmod u-x,g-wx,o-rwx "$f" 2>/dev/null || true ;;
          *) chmod u-x,g-wx,o-rwx "$f" 2>/dev/null || true ;;
        esac
        ;;
    esac
  done < <(find /var/log -xdev -type f -print0 2>/dev/null)
  ok "6.1.3.1 /var/log file modes tightened. Owners were not rewritten when a service user already owns the file."
}

cis_6_2_1_1() { apt_install auditd audispd-plugins && ok "6.2.1.1 auditd installed" || fail "6.2.1.1 install failed"; }
cis_6_2_1_2() {
  if [[ "$DRY_RUN" == 1 ]]; then ok "6.2.1.2 (dry-run)"; return 0; fi
  systemctl unmask auditd 2>/dev/null || true
  systemctl enable auditd && systemctl start auditd && ok "6.2.1.2 auditd enabled" || fail "6.2.1.2 auditd failed to start"
}
cis_6_2_1_3() { grub_add "audit=1"; ok "6.2.1.3 audit=1 staged on the kernel command line"; }
cis_6_2_1_4() { grub_add "audit_backlog_limit=8192"; ok "6.2.1.4 audit_backlog_limit=8192 staged"; }

audit_set() {
  local key="$1" value="$2"
  [[ -f /etc/audit/auditd.conf ]] || return 0
  set_kv /etc/audit/auditd.conf "$key" "$value"
}

cis_6_2_2_1() { audit_set max_log_file "$AUDIT_MAX_LOG_FILE"; ok "6.2.2.1 max_log_file = ${AUDIT_MAX_LOG_FILE}"; }
cis_6_2_2_2() { audit_set max_log_file_action keep_logs; ok "6.2.2.2 max_log_file_action = keep_logs"; }
cis_6_2_2_3() { audit_set disk_full_action halt; audit_set disk_error_action halt; warn "6.2.2.3 a full audit disk will halt the machine"; ok "6.2.2.3 disk_full_action=halt disk_error_action=halt"; }
cis_6_2_2_4() { audit_set space_left_action email; audit_set admin_space_left_action single; warn "6.2.2.4 space_left_action=email needs an MTA"; ok "6.2.2.4 space_left_action=email admin_space_left_action=single"; }

audit_rules_file() {
  local name="$1"
  write_file "/etc/audit/rules.d/${name}" 640
}

cis_6_2_3_1() { audit_rules_file 50-scope.rules <<'EOF'
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
EOF
  ok "6.2.3.1 scope rules"; }
cis_6_2_3_2() { audit_rules_file 50-user_emulation.rules <<'EOF'
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
EOF
  ok "6.2.3.2 user_emulation"; }
cis_6_2_3_3() { audit_rules_file 50-sudo.rules <<'EOF'
-w /var/log/sudo.log -p wa -k sudo_log_file
EOF
  ok "6.2.3.3 sudo log watch"; }
cis_6_2_3_4() { audit_rules_file 50-time-change.rules <<'EOF'
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
EOF
  ok "6.2.3.4 time-change"; }
cis_6_2_3_5() { audit_rules_file 50-system_locale.rules <<'EOF'
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale
EOF
  ok "6.2.3.5 system-locale"; }

cis_6_2_3_6() {
  local uid part path
  uid="$(uid_min)"
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.2.3.6 privileged rules (dry-run)"
    return 0
  fi
  : > /etc/audit/rules.d/50-privileged.rules
  while read -r _ part _; do
    [[ -n "$part" ]] || continue
    find "$part" -xdev -perm /6000 -type f 2>/dev/null | while read -r path; do
      printf -- '-a always,exit -F path=%s -F perm=x -F auid>=%s -F auid!=unset -k privileged\n' "$path" "$uid"
    done
  done < <(findmnt -n -r -o TARGET,OPTIONS | awk '$2 !~ /(noexec|nosuid)/ {print $1}') >> /etc/audit/rules.d/50-privileged.rules
  chmod 0640 /etc/audit/rules.d/50-privileged.rules
  ok "6.2.3.6 privileged command rules regenerated from local setuid/setgid files"
}

cis_6_2_3_7() {
  local uid; uid="$(uid_min)"
  audit_rules_file 50-access.rules <<EOF
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=unset -k access
EOF
  ok "6.2.3.7 access rules"
}
cis_6_2_3_8() { audit_rules_file 50-identity.rules <<'EOF'
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
EOF
  ok "6.2.3.8 identity"; }
cis_6_2_3_9() {
  local uid; uid="$(uid_min)"
  audit_rules_file 50-perm_mod.rules <<EOF
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${uid} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${uid} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=unset -F key=perm_mod
EOF
  ok "6.2.3.9 perm_mod"
}
cis_6_2_3_10() {
  local uid; uid="$(uid_min)"
  audit_rules_file 50-mounts.rules <<EOF
-a always,exit -F arch=b32 -S mount -F auid>=${uid} -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=${uid} -F auid!=unset -k mounts
EOF
  ok "6.2.3.10 mounts"
}
cis_6_2_3_11() { audit_rules_file 50-session.rules <<'EOF'
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
EOF
  ok "6.2.3.11 session"; }
cis_6_2_3_12() { audit_rules_file 50-login.rules <<'EOF'
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
EOF
  ok "6.2.3.12 logins"; }
cis_6_2_3_13() {
  local uid; uid="$(uid_min)"
  audit_rules_file 50-delete.rules <<EOF
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${uid} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${uid} -F auid!=unset -F key=delete
EOF
  ok "6.2.3.13 delete"
}
cis_6_2_3_14() { audit_rules_file 50-MAC-policy.rules <<'EOF'
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
  ok "6.2.3.14 MAC-policy"; }

audit_watch_bin() {
  local id="$1" path="$2" key="$3" file="$4" uid
  uid="$(uid_min)"
  if [[ ! -e "$path" ]]; then
    ok "${id} ${path} absent"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "${id} (dry-run)"
    return 0
  fi
  mkdir -p /etc/audit/rules.d
  printf -- '-a always,exit -F path=%s -F perm=x -F auid>=%s -F auid!=unset -k %s\n' "$path" "$uid" "$key" >> "/etc/audit/rules.d/${file}"
  ok "${id} watch ${path}"
}
cis_6_2_3_15() { audit_watch_bin "6.2.3.15" /usr/bin/chcon perm_chng 50-perm_chng.rules; }
cis_6_2_3_16() { audit_watch_bin "6.2.3.16" /usr/bin/setfacl perm_chng 50-perm_chng.rules; }
cis_6_2_3_17() { audit_watch_bin "6.2.3.17" /usr/bin/chacl perm_chng 50-perm_chng.rules; }
cis_6_2_3_18() { audit_watch_bin "6.2.3.18" /usr/sbin/usermod usermod 50-usermod.rules; }
cis_6_2_3_19() {
  local uid kmod
  uid="$(uid_min)"
  kmod="$(command -v kmod || echo /usr/bin/kmod)"
  audit_rules_file 50-kernel_modules.rules <<EOF
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${uid} -F auid!=unset -k kernel_modules
-a always,exit -F path=${kmod} -F perm=x -F auid>=${uid} -F auid!=unset -k kernel_modules
EOF
  ok "6.2.3.19 kernel_modules"
}
cis_6_2_3_20() {
  if [[ "$AUDIT_IMMUTABLE" == 1 ]]; then
    if [[ "$DRY_RUN" != 1 ]]; then
      mkdir -p /etc/audit/rules.d
      printf '\n%s\n' '-e 2' > /etc/audit/rules.d/99-finalize.rules
      chmod 0640 /etc/audit/rules.d/99-finalize.rules || true
      chown root:root /etc/audit/rules.d/99-finalize.rules || true
    fi
  else
    log "6.2.3.20 AUDIT_IMMUTABLE=0; -e 2 not written"
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.2.3.20 (dry-run)"
    return 0
  fi
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || warn "6.2.3.20 augenrules --load failed (reboot if audit is already immutable)"
  fi
  if [[ "$AUDIT_IMMUTABLE" == 1 ]]; then
    note_reboot "audit rule -e 2 does not lock the running rule set until reboot. After that, rule changes also need a reboot."
    ok "6.2.3.20 -e 2 written"
  else
    manual "6.2.3.20 rules were not made immutable. The benchmark fails until -e 2 is last and the system is rebooted."
  fi
}
cis_6_2_3_21() {
  if [[ "$DRY_RUN" == 1 ]]; then
    manual "6.2.3.21 running config versus disk is checked after augenrules --load. Reboot if auditctl -s shows enabled 2."
    return 0
  fi
  if command -v augenrules >/dev/null 2>&1; then
    if augenrules --check 2>&1 | grep -q 'No change'; then
      ok "6.2.3.21 augenrules --check: No change"
    else
      manual "6.2.3.21 running audit rules differ from disk. Run augenrules --load, or reboot if the rules are immutable."
    fi
  else
    manual "6.2.3.21 augenrules is not installed"
  fi
}

audit_log_dir() {
  local d
  d="$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/{gsub(/ /,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)"
  d="$(dirname "${d:-/var/log/audit/audit.log}")"
  printf '%s' "$d"
}

cis_6_2_4_1() {
  local d f
  d="$(audit_log_dir)"
  [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.1 (dry-run)"; return 0; }
  [[ -d "$d" ]] || { manual "6.2.4.1 ${d} missing"; return 0; }
  find "$d" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} + 2>/dev/null || true
  ok "6.2.4.1 audit logs mode tightened in ${d}"
}
cis_6_2_4_2() {
  local d
  d="$(audit_log_dir)"
  [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.2 (dry-run)"; return 0; }
  find "$d" -type f ! -user root -exec chown root {} + 2>/dev/null || true
  ok "6.2.4.2 audit logs owned by root"
}
cis_6_2_4_3() {
  audit_set log_group adm
  local d
  d="$(audit_log_dir)"
  [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.3 (dry-run)"; return 0; }
  find "$d" -type f ! -group adm ! -group root -exec chgrp adm {} + 2>/dev/null || true
  systemctl restart auditd 2>/dev/null || true
  ok "6.2.4.3 log_group = adm"
}
cis_6_2_4_4() {
  local d; d="$(audit_log_dir)"
  [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.4 (dry-run)"; return 0; }
  [[ -d "$d" ]] && chmod g-w,o-rwx "$d"
  ok "6.2.4.4 ${d} mode $(stat -c '%a' "$d" 2>/dev/null || echo n/a)"
}
cis_6_2_4_5() {
  [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.5 (dry-run)"; return 0; }
  find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) -perm /0137 -exec chmod u-x,g-wx,o-rwx {} + 2>/dev/null || true
  ok "6.2.4.5 audit config modes"
}
cis_6_2_4_6() { [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.6 (dry-run)"; return 0; }; find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} + 2>/dev/null || true; ok "6.2.4.6 audit config owned by root"; }
cis_6_2_4_7() { [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.7 (dry-run)"; return 0; }; find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} + 2>/dev/null || true; ok "6.2.4.7 audit config grouped root"; }

audit_tools() {
  local t
  for t in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace /usr/sbin/auditd /usr/sbin/augenrules; do
    [[ -e "$t" ]] && printf '%s\n' "$t"
  done | awk '!seen[$0]++'
}
cis_6_2_4_8() { [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.8 (dry-run)"; return 0; }; audit_tools | while read -r t; do chmod go-w "$t"; done; ok "6.2.4.8 audit tools not group/world writable"; }
cis_6_2_4_9() { [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.9 (dry-run)"; return 0; }; audit_tools | while read -r t; do chown root "$t"; done; ok "6.2.4.9 audit tools owned by root"; }
cis_6_2_4_10() { [[ "$DRY_RUN" == 1 ]] && { ok "6.2.4.10 (dry-run)"; return 0; }; audit_tools | while read -r t; do chgrp root "$t"; done; ok "6.2.4.10 audit tools grouped root"; }

cis_6_3_1() { apt_install aide aide-common && ok "6.3.1 aide installed" || fail "6.3.1 install failed"; }
cis_6_3_3() {
  local p
  p="$(readlink -f /sbin 2>/dev/null || echo /usr/sbin)"
  if [[ "$DRY_RUN" != 1 && -f /etc/aide/aide.conf ]] && ! grep -q '# Audit Tools' /etc/aide/aide.conf; then
    backup_file /etc/aide/aide.conf
    cat >> /etc/aide/aide.conf <<EOF

# Audit Tools
${p}/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
${p}/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
${p}/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
${p}/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
${p}/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
${p}/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF
  fi
  if [[ "$AIDE_INIT" != 1 ]]; then
    manual "6.3.3 aide.conf updated if present, but AIDE_INIT=0 so the database was not built."
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "6.3.3 aideinit (dry-run)"
    return 0
  fi
  if command -v aideinit >/dev/null 2>&1; then
    warn "6.3.3 aideinit walks the filesystem and can take a long time"
    aideinit && { [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; ok "6.3.3 AIDE database initialized"; } || fail "6.3.3 aideinit failed"
  else
    fail "6.3.3 aideinit missing"
  fi
}
cis_6_3_2() {
  if [[ "$DRY_RUN" == 1 ]]; then ok "6.3.2 (dry-run)"; return 0; fi
  systemctl unmask dailyaidecheck.timer dailyaidecheck.service 2>/dev/null || true
  systemctl --now enable dailyaidecheck.timer && ok "6.3.2 dailyaidecheck.timer enabled" || fail "6.3.2 could not enable dailyaidecheck.timer"
}

# =============================================================================
# 7 Maintenance
# =============================================================================

perm_file() {
  local id="$1" file="$2" mode="$3" user="$4" group="$5"
  if [[ ! -e "$file" ]]; then
    manual "${id} ${file} does not exist"
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    ok "${id} (dry-run)"
    return 0
  fi
  chown "${user}:${group}" "$file"
  chmod "$mode" "$file"
  ok "${id} $(stat -c '%a %U:%G %n' "$file")"
}
shadow_group_name() { getent group shadow >/dev/null && echo shadow || echo root; }

cis_7_1_1() { perm_file "7.1.1" /etc/passwd u-x,go-wx root root; }
cis_7_1_2() { perm_file "7.1.2" /etc/passwd- u-x,go-wx root root; }
cis_7_1_3() { perm_file "7.1.3" /etc/group u-x,go-wx root root; }
cis_7_1_4() { perm_file "7.1.4" /etc/group- u-x,go-wx root root; }
cis_7_1_5() { perm_file "7.1.5" /etc/shadow u-x,g-wx,o-rwx root "$(shadow_group_name)"; }
cis_7_1_6() { perm_file "7.1.6" /etc/shadow- u-x,g-wx,o-rwx root "$(shadow_group_name)"; }
cis_7_1_7() { perm_file "7.1.7" /etc/gshadow u-x,g-wx,o-rwx root "$(shadow_group_name)"; }
cis_7_1_8() { perm_file "7.1.8" /etc/gshadow- u-x,g-wx,o-rwx root "$(shadow_group_name)"; }
cis_7_1_9() { perm_file "7.1.9" /etc/shells u-x,go-wx root root; }
cis_7_1_10() {
  local f found=0
  for f in /etc/security/opasswd /etc/security/opasswd.old; do
    [[ -e "$f" ]] || continue
    found=1
    perm_file "7.1.10" "$f" u-x,go-rwx root root
  done
  [[ "$found" == 1 ]] || ok "7.1.10 opasswd not present yet"
}

cis_7_1_11() {
  [[ "$DRY_RUN" == 1 ]] && { ok "7.1.11 (dry-run)"; return 0; }
  local mp fst opts
  while read -r mp fst opts; do
    [[ "$fst" =~ ^(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)$ ]] && continue
    find "$mp" -xdev \( -path '/run/user/*' -o -path '/proc/*' -o -path '*/containerd/*' -o -path '*/kubelet/pods/*' -o -path '*/kubelet/plugins/*' -o -path '/sys/*' -o -path '/snap/*' \) -prune -o -type f -perm -0002 -print 2>/dev/null | while read -r f; do
      chmod o-w "$f" || true
      emit DETAIL "removed other-write on ${f}"
    done
    find "$mp" -xdev \( -path '/tmp' -o -path '/var/tmp' -o -path '/dev/shm' -o -path '/run/user/*' \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | while read -r d; do
      chmod a+t "$d" || true
      emit DETAIL "sticky bit set on ${d}"
    done
  done < <(findmnt -n -r -o TARGET,FSTYPE,OPTIONS)
  ok "7.1.11 world-writable files and directories reviewed on local mounts"
}

cis_7_1_12() {
  emit INFO "unowned or ungrouped files:"
  find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 200 | while read -r f; do
    emit DETAIL "unowned: ${f}"
    if [[ "$FIX_UNOWNED" == 1 && "$DRY_RUN" != 1 ]]; then
      chown root:root "$f" || true
    fi
  done
  if [[ "$FIX_UNOWNED" == 1 ]]; then
    ok "7.1.12 unowned files chowned root:root where found (first 200 logged)"
  else
    manual "7.1.12 unowned files were only reported. Pass --fix-unowned to chown root:root. Review the list first."
  fi
}

cis_7_1_13() {
  local out="${SCRIPT_DIR}/cis-mint22-suid-sgid.txt"
  emit INFO "writing SUID/SGID list to ${out}"
  if [[ "$DRY_RUN" == 1 ]]; then
    manual "7.1.13 SUID/SGID review is Manual. No bits were removed."
    return 0
  fi
  : > "$out"
  findmnt -n -r -o TARGET,OPTIONS | awk '$2 !~ /(noexec|nosuid)/ {print $1}' | while read -r mp; do
    find "$mp" -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
  done >> "$out" || true
  emit INFO "SUID/SGID count: $(wc -l < "$out" | tr -d ' ')"
  manual "7.1.13 review ${out}. This script does not strip SUID/SGID bits."
}

cis_7_2_1() {
  if awk -F: '($2 != "x") { found=1 } END { exit !found }' /etc/passwd; then
    [[ "$DRY_RUN" == 1 ]] || pwconv || fail "7.2.1 pwconv failed"
    ok "7.2.1 pwconv run so passwords are shadowed"
  else
    ok "7.2.1 all /etc/passwd password fields are x"
  fi
}
cis_7_2_2() {
  local user
  while read -r user; do
    [[ -n "$user" ]] || continue
    if [[ "$DRY_RUN" == 1 ]]; then
      log "DRY-RUN: passwd -l ${user}"
    else
      passwd -l "$user" || fail "7.2.2 could not lock ${user}"
    fi
    emit INFO "7.2.2 locked empty password: ${user}"
  done < <(awk -F: '($2==""){print $1}' /etc/shadow)
  ok "7.2.2 empty shadow passwords locked"
}
cis_7_2_3() {
  local gid
  while read -r gid; do
    getent group "$gid" >/dev/null || manual "7.2.3 passwd GID ${gid} has no matching group"
  done < <(awk -F: '{print $4}' /etc/passwd | sort -u)
  ok "7.2.3 passwd GIDs compared to /etc/group"
}
cis_7_2_4() {
  if [[ "$DRY_RUN" != 1 && -f /etc/group ]]; then
    backup_file /etc/group
    sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group
  fi
  local gid users
  gid="$(getent group shadow | awk -F: '{print $3}')"
  if [[ -n "$gid" ]]; then
    users="$(awk -F: -v g="$gid" '($4==g){print $1}' /etc/passwd)"
    [[ -n "$users" ]] && manual "7.2.4 these users have primary GID shadow and were not moved: ${users}"
  fi
  ok "7.2.4 shadow group member list cleared"
}
report_duplicates() {
  local id="$1" file="$2" field="$3" label="$4" line
  line="$(cut -d: -f"$field" "$file" | sort | uniq -c | awk '$1>1')"
  if [[ -n "$line" ]]; then
    emit DETAIL "${line}"
    manual "${id} duplicate ${label} exist. Fix them by hand. Output is above."
  else
    ok "${id} no duplicate ${label}"
  fi
}
cis_7_2_5() { report_duplicates "7.2.5" /etc/passwd 3 "UIDs"; }
cis_7_2_6() { report_duplicates "7.2.6" /etc/group 3 "GIDs"; }
cis_7_2_7() { report_duplicates "7.2.7" /etc/passwd 1 "user names"; }
cis_7_2_8() { report_duplicates "7.2.8" /etc/group 1 "group names"; }

cis_7_2_9() {
  local user home shell min
  min="$(uid_min)"
  [[ "$DRY_RUN" == 1 ]] && { ok "7.2.9 (dry-run)"; return 0; }
  while IFS=: read -r user _ uid _ _ home shell; do
    (( uid >= min )) || continue
    grep -Fxq "$shell" /etc/shells 2>/dev/null || continue
    [[ "$(basename "$shell")" == nologin ]] && continue
    if [[ ! -d "$home" ]]; then
      manual "7.2.9 ${user} home ${home} is missing"
      continue
    fi
    chown "$user" "$home" || true
    chmod g-w,o-rwx "$home" || true
  done < /etc/passwd
  ok "7.2.9 interactive home directories are owned by the user and not group/world writable"
}

cis_7_2_10() {
  local user home shell min group f base
  min="$(uid_min)"
  [[ "$DRY_RUN" == 1 ]] && { ok "7.2.10 (dry-run)"; return 0; }
  while IFS=: read -r user _ uid _ gid home shell; do
    (( uid >= min )) || continue
    grep -Fxq "$shell" /etc/shells 2>/dev/null || continue
    [[ -d "$home" ]] || continue
    group="$(id -gn "$user" 2>/dev/null || echo "$gid")"
    for f in "$home"/.[!.]* "$home"/..?*; do
      [[ -e "$f" ]] || continue
      base="$(basename "$f")"
      case "$base" in
        .|..) continue ;;
        .forward|.rhost|.rhosts)
          manual "7.2.10 ${user} has ${f}. Delete it by hand."
          ;;
        .netrc|.bash_history)
          chown "$user:$group" "$f" 2>/dev/null || true
          chmod u-x,go-rwx "$f" 2>/dev/null || true
          ;;
        *)
          chown "$user:$group" "$f" 2>/dev/null || true
          chmod u-x,go-wx "$f" 2>/dev/null || true
          ;;
      esac
    done
  done < /etc/passwd
  ok "7.2.10 dotfile modes tightened. .forward and .rhosts were not deleted."
}
register_all() {
  local id level fn
  register "1.1.1.1" L1 cis_1_1_1_1 "CIS 1.1.1.1"
  register "1.1.1.2" L1 cis_1_1_1_2 "CIS 1.1.1.2"
  register "1.1.1.3" L1 cis_1_1_1_3 "CIS 1.1.1.3"
  register "1.1.1.4" L1 cis_1_1_1_4 "CIS 1.1.1.4"
  register "1.1.1.5" L1 cis_1_1_1_5 "CIS 1.1.1.5"
  register "1.1.1.6" L2 cis_1_1_1_6 "CIS 1.1.1.6"
  register "1.1.1.7" L2 cis_1_1_1_7 "CIS 1.1.1.7"
  register "1.1.1.8" L2 cis_1_1_1_8 "CIS 1.1.1.8"
  register "1.1.1.9" L2 cis_1_1_1_9 "CIS 1.1.1.9"
  register "1.1.1.10" L1 cis_1_1_1_10 "CIS 1.1.1.10"
  register "1.1.2.1.1" L1 cis_1_1_2_1_1 "CIS 1.1.2.1.1"
  register "1.1.2.1.2" L1 cis_1_1_2_1_2 "CIS 1.1.2.1.2"
  register "1.1.2.1.3" L1 cis_1_1_2_1_3 "CIS 1.1.2.1.3"
  register "1.1.2.1.4" L1 cis_1_1_2_1_4 "CIS 1.1.2.1.4"
  register "1.1.2.2.1" L1 cis_1_1_2_2_1 "CIS 1.1.2.2.1"
  register "1.1.2.2.2" L1 cis_1_1_2_2_2 "CIS 1.1.2.2.2"
  register "1.1.2.2.3" L1 cis_1_1_2_2_3 "CIS 1.1.2.2.3"
  register "1.1.2.2.4" L1 cis_1_1_2_2_4 "CIS 1.1.2.2.4"
  register "1.1.2.3.1" L2 cis_1_1_2_3_1 "CIS 1.1.2.3.1"
  register "1.1.2.3.2" L1 cis_1_1_2_3_2 "CIS 1.1.2.3.2"
  register "1.1.2.3.3" L1 cis_1_1_2_3_3 "CIS 1.1.2.3.3"
  register "1.1.2.4.1" L2 cis_1_1_2_4_1 "CIS 1.1.2.4.1"
  register "1.1.2.4.2" L1 cis_1_1_2_4_2 "CIS 1.1.2.4.2"
  register "1.1.2.4.3" L1 cis_1_1_2_4_3 "CIS 1.1.2.4.3"
  register "1.1.2.5.1" L2 cis_1_1_2_5_1 "CIS 1.1.2.5.1"
  register "1.1.2.5.2" L1 cis_1_1_2_5_2 "CIS 1.1.2.5.2"
  register "1.1.2.5.3" L1 cis_1_1_2_5_3 "CIS 1.1.2.5.3"
  register "1.1.2.5.4" L1 cis_1_1_2_5_4 "CIS 1.1.2.5.4"
  register "1.1.2.6.1" L2 cis_1_1_2_6_1 "CIS 1.1.2.6.1"
  register "1.1.2.6.2" L1 cis_1_1_2_6_2 "CIS 1.1.2.6.2"
  register "1.1.2.6.3" L1 cis_1_1_2_6_3 "CIS 1.1.2.6.3"
  register "1.1.2.6.4" L1 cis_1_1_2_6_4 "CIS 1.1.2.6.4"
  register "1.1.2.7.1" L2 cis_1_1_2_7_1 "CIS 1.1.2.7.1"
  register "1.1.2.7.2" L1 cis_1_1_2_7_2 "CIS 1.1.2.7.2"
  register "1.1.2.7.3" L1 cis_1_1_2_7_3 "CIS 1.1.2.7.3"
  register "1.1.2.7.4" L1 cis_1_1_2_7_4 "CIS 1.1.2.7.4"
  register "1.2.1.1" L1 cis_1_2_1_1 "CIS 1.2.1.1"
  register "1.2.1.2" L1 cis_1_2_1_2 "CIS 1.2.1.2"
  register "1.2.2.1" L1 cis_1_2_2_1 "CIS 1.2.2.1"
  register "1.2.2.2" L1 cis_1_2_2_2 "CIS 1.2.2.2"
  register "1.3.1.1" L1 cis_1_3_1_1 "CIS 1.3.1.1"
  register "1.3.1.2" L1 cis_1_3_1_2 "CIS 1.3.1.2"
  register "1.3.1.3" L1 cis_1_3_1_3 "CIS 1.3.1.3"
  register "1.3.1.4" L1 cis_1_3_1_4 "CIS 1.3.1.4"
  register "1.4.1" L1 cis_1_4_1 "CIS 1.4.1"
  register "1.4.2" L1 cis_1_4_2 "CIS 1.4.2"
  register "1.5.1" L1 cis_1_5_1 "CIS 1.5.1"
  register "1.5.2" L1 cis_1_5_2 "CIS 1.5.2"
  register "1.5.3" L1 cis_1_5_3 "CIS 1.5.3"
  register "1.5.4" L1 cis_1_5_4 "CIS 1.5.4"
  register "1.5.5" L1 cis_1_5_5 "CIS 1.5.5"
  register "1.5.6" L1 cis_1_5_6 "CIS 1.5.6"
  register "1.6.1" L1 cis_1_6_1 "CIS 1.6.1"
  register "1.6.2" L1 cis_1_6_2 "CIS 1.6.2"
  register "1.6.3" L1 cis_1_6_3 "CIS 1.6.3"
  register "1.6.4" L1 cis_1_6_4 "CIS 1.6.4"
  register "1.6.5" L1 cis_1_6_5 "CIS 1.6.5"
  register "1.6.6" L1 cis_1_6_6 "CIS 1.6.6"
  register "1.7.1" L1 cis_1_7_1 "CIS 1.7.1"
  register "1.7.2" L1 cis_1_7_2 "CIS 1.7.2"
  register "1.7.3" L1 cis_1_7_3 "CIS 1.7.3"
  register "2.1.1" L2 cis_2_1_1 "CIS 2.1.1"
  register "2.1.2" L2 cis_2_1_2 "CIS 2.1.2"
  register "2.1.3" L1 cis_2_1_3 "CIS 2.1.3"
  register "2.1.4" L1 cis_2_1_4 "CIS 2.1.4"
  register "2.1.5" L1 cis_2_1_5 "CIS 2.1.5"
  register "2.1.6" L1 cis_2_1_6 "CIS 2.1.6"
  register "2.1.7" L1 cis_2_1_7 "CIS 2.1.7"
  register "2.1.8" L1 cis_2_1_8 "CIS 2.1.8"
  register "2.1.9" L1 cis_2_1_9 "CIS 2.1.9"
  register "2.1.10" L1 cis_2_1_10 "CIS 2.1.10"
  register "2.1.11" L1 cis_2_1_11 "CIS 2.1.11"
  register "2.1.12" L2 cis_2_1_12 "CIS 2.1.12"
  register "2.1.13" L1 cis_2_1_13 "CIS 2.1.13"
  register "2.1.14" L1 cis_2_1_14 "CIS 2.1.14"
  register "2.1.15" L1 cis_2_1_15 "CIS 2.1.15"
  register "2.1.16" L1 cis_2_1_16 "CIS 2.1.16"
  register "2.1.17" L1 cis_2_1_17 "CIS 2.1.17"
  register "2.1.18" L1 cis_2_1_18 "CIS 2.1.18"
  register "2.1.19" L1 cis_2_1_19 "CIS 2.1.19"
  register "2.1.20" L1 cis_2_1_20 "CIS 2.1.20"
  register "2.1.21" L1 cis_2_1_21 "CIS 2.1.21"
  register "2.1.22" L1 cis_2_1_22 "CIS 2.1.22"
  register "2.1.23" L1 cis_2_1_23 "CIS 2.1.23"
  register "2.2.1" L1 cis_2_2_1 "CIS 2.2.1"
  register "2.2.2" L1 cis_2_2_2 "CIS 2.2.2"
  register "2.2.3" L1 cis_2_2_3 "CIS 2.2.3"
  register "2.2.4" L1 cis_2_2_4 "CIS 2.2.4"
  register "2.2.5" L1 cis_2_2_5 "CIS 2.2.5"
  register "2.2.6" L1 cis_2_2_6 "CIS 2.2.6"
  register "2.3.1.1" L1 cis_2_3_1_1 "CIS 2.3.1.1"
  register "2.3.2.1" L1 cis_2_3_2_1 "CIS 2.3.2.1"
  register "2.3.2.2" L1 cis_2_3_2_2 "CIS 2.3.2.2"
  register "2.4.1.1" L1 cis_2_4_1_1 "CIS 2.4.1.1"
  register "2.4.1.2" L1 cis_2_4_1_2 "CIS 2.4.1.2"
  register "2.4.1.3" L1 cis_2_4_1_3 "CIS 2.4.1.3"
  register "2.4.1.4" L1 cis_2_4_1_4 "CIS 2.4.1.4"
  register "2.4.1.5" L1 cis_2_4_1_5 "CIS 2.4.1.5"
  register "2.4.1.6" L1 cis_2_4_1_6 "CIS 2.4.1.6"
  register "2.4.1.7" L1 cis_2_4_1_7 "CIS 2.4.1.7"
  register "2.4.1.8" L1 cis_2_4_1_8 "CIS 2.4.1.8"
  register "2.4.1.9" L1 cis_2_4_1_9 "CIS 2.4.1.9"
  register "2.4.2.1" L1 cis_2_4_2_1 "CIS 2.4.2.1"
  register "3.1.1" L1 cis_3_1_1 "CIS 3.1.1"
  register "3.1.2" L2 cis_3_1_2 "CIS 3.1.2"
  register "3.2.1" L1 cis_3_2_1 "CIS 3.2.1"
  register "3.2.2" L1 cis_3_2_2 "CIS 3.2.2"
  register "3.2.3" L1 cis_3_2_3 "CIS 3.2.3"
  register "3.2.4" L1 cis_3_2_4 "CIS 3.2.4"
  register "3.3.1" L1 cis_3_3_1 "CIS 3.3.1"
  register "3.3.2" L1 cis_3_3_2 "CIS 3.3.2"
  register "3.3.3" L1 cis_3_3_3 "CIS 3.3.3"
  register "3.3.4" L1 cis_3_3_4 "CIS 3.3.4"
  register "3.3.5" L1 cis_3_3_5 "CIS 3.3.5"
  register "3.3.6" L1 cis_3_3_6 "CIS 3.3.6"
  register "3.3.7" L1 cis_3_3_7 "CIS 3.3.7"
  register "3.3.8" L1 cis_3_3_8 "CIS 3.3.8"
  register "3.3.9" L1 cis_3_3_9 "CIS 3.3.9"
  register "3.3.10" L1 cis_3_3_10 "CIS 3.3.10"
  register "3.3.11" L1 cis_3_3_11 "CIS 3.3.11"
  register "4.1.1" L1 cis_4_1_1 "CIS 4.1.1"
  register "4.1.3" L1 cis_4_1_3 "CIS 4.1.3"
  register "4.1.4" L1 cis_4_1_4 "CIS 4.1.4"
  register "4.1.2" L1 cis_4_1_2 "CIS 4.1.2"
  register "5.1.1" L1 cis_5_1_1 "CIS 5.1.1"
  register "5.1.2" L1 cis_5_1_2 "CIS 5.1.2"
  register "5.1.3" L1 cis_5_1_3 "CIS 5.1.3"
  register "5.1.4" L2 cis_5_1_4 "CIS 5.1.4"
  register "5.1.5" L1 cis_5_1_5 "CIS 5.1.5"
  register "5.1.6" L1 cis_5_1_6 "CIS 5.1.6"
  register "5.1.7" L1 cis_5_1_7 "CIS 5.1.7"
  register "5.2.1.1" L1 cis_5_2_1_1 "CIS 5.2.1.1"
  register "5.2.1.2" L1 cis_5_2_1_2 "CIS 5.2.1.2"
  register "5.2.1.3" L1 cis_5_2_1_3 "CIS 5.2.1.3"
  register "5.2.2.1" L1 cis_5_2_2_1 "CIS 5.2.2.1"
  register "5.2.2.2" L1 cis_5_2_2_2 "CIS 5.2.2.2"
  register "5.2.2.3" L1 cis_5_2_2_3 "CIS 5.2.2.3"
  register "5.2.2.4" L1 cis_5_2_2_4 "CIS 5.2.2.4"
  register "5.2.3.1.1" L1 cis_5_2_3_1_1 "CIS 5.2.3.1.1"
  register "5.2.3.1.2" L1 cis_5_2_3_1_2 "CIS 5.2.3.1.2"
  register "5.2.3.1.3" L2 cis_5_2_3_1_3 "CIS 5.2.3.1.3"
  register "5.2.3.2.1" L1 cis_5_2_3_2_1 "CIS 5.2.3.2.1"
  register "5.2.3.2.2" L1 cis_5_2_3_2_2 "CIS 5.2.3.2.2"
  register "5.2.3.2.3" L2 cis_5_2_3_2_3 "CIS 5.2.3.2.3"
  register "5.2.3.2.4" L1 cis_5_2_3_2_4 "CIS 5.2.3.2.4"
  register "5.2.3.2.5" L1 cis_5_2_3_2_5 "CIS 5.2.3.2.5"
  register "5.2.3.2.6" L1 cis_5_2_3_2_6 "CIS 5.2.3.2.6"
  register "5.2.3.2.7" L1 cis_5_2_3_2_7 "CIS 5.2.3.2.7"
  register "5.2.3.2.8" L1 cis_5_2_3_2_8 "CIS 5.2.3.2.8"
  register "5.2.3.3.1" L1 cis_5_2_3_3_1 "CIS 5.2.3.3.1"
  register "5.2.3.3.2" L1 cis_5_2_3_3_2 "CIS 5.2.3.3.2"
  register "5.2.3.3.3" L1 cis_5_2_3_3_3 "CIS 5.2.3.3.3"
  register "5.2.3.4.1" L1 cis_5_2_3_4_1 "CIS 5.2.3.4.1"
  register "5.2.3.4.2" L1 cis_5_2_3_4_2 "CIS 5.2.3.4.2"
  register "5.2.3.4.3" L1 cis_5_2_3_4_3 "CIS 5.2.3.4.3"
  register "5.2.3.4.4" L1 cis_5_2_3_4_4 "CIS 5.2.3.4.4"
  register "5.3.1.1" L2 cis_5_3_1_1 "CIS 5.3.1.1"
  register "5.3.1.2" L2 cis_5_3_1_2 "CIS 5.3.1.2"
  register "5.3.1.3" L1 cis_5_3_1_3 "CIS 5.3.1.3"
  register "5.3.1.4" L1 cis_5_3_1_4 "CIS 5.3.1.4"
  register "5.3.1.5" L2 cis_5_3_1_5 "CIS 5.3.1.5"
  register "5.3.1.6" L1 cis_5_3_1_6 "CIS 5.3.1.6"
  register "5.3.2.1" L1 cis_5_3_2_1 "CIS 5.3.2.1"
  register "5.3.2.2" L1 cis_5_3_2_2 "CIS 5.3.2.2"
  register "5.3.2.3" L1 cis_5_3_2_3 "CIS 5.3.2.3"
  register "5.3.2.4" L1 cis_5_3_2_4 "CIS 5.3.2.4"
  register "5.3.2.5" L1 cis_5_3_2_5 "CIS 5.3.2.5"
  register "5.3.2.6" L1 cis_5_3_2_6 "CIS 5.3.2.6"
  register "5.3.2.7" L1 cis_5_3_2_7 "CIS 5.3.2.7"
  register "5.3.2.8" L1 cis_5_3_2_8 "CIS 5.3.2.8"
  register "5.3.3.1" L2 cis_5_3_3_1 "CIS 5.3.3.1"
  register "5.3.3.2" L1 cis_5_3_3_2 "CIS 5.3.3.2"
  register "5.3.3.3" L1 cis_5_3_3_3 "CIS 5.3.3.3"
  register "6.1.1.1" L1 cis_6_1_1_1 "CIS 6.1.1.1"
  register "6.1.1.2" L1 cis_6_1_1_2 "CIS 6.1.1.2"
  register "6.1.1.3" L1 cis_6_1_1_3 "CIS 6.1.1.3"
  register "6.1.2.1.1" L2 cis_6_1_2_1_1 "CIS 6.1.2.1.1"
  register "6.1.2.1.2" L2 cis_6_1_2_1_2 "CIS 6.1.2.1.2"
  register "6.1.2.1.3" L2 cis_6_1_2_1_3 "CIS 6.1.2.1.3"
  register "6.1.2.1.4" L2 cis_6_1_2_1_4 "CIS 6.1.2.1.4"
  register "6.1.2.2" L1 cis_6_1_2_2 "CIS 6.1.2.2"
  register "6.1.2.3" L1 cis_6_1_2_3 "CIS 6.1.2.3"
  register "6.1.2.4" L1 cis_6_1_2_4 "CIS 6.1.2.4"
  register "6.1.3.1" L1 cis_6_1_3_1 "CIS 6.1.3.1"
  register "6.2.1.1" L2 cis_6_2_1_1 "CIS 6.2.1.1"
  register "6.2.1.2" L2 cis_6_2_1_2 "CIS 6.2.1.2"
  register "6.2.1.3" L2 cis_6_2_1_3 "CIS 6.2.1.3"
  register "6.2.1.4" L2 cis_6_2_1_4 "CIS 6.2.1.4"
  register "6.2.2.1" L2 cis_6_2_2_1 "CIS 6.2.2.1"
  register "6.2.2.2" L2 cis_6_2_2_2 "CIS 6.2.2.2"
  register "6.2.2.3" L2 cis_6_2_2_3 "CIS 6.2.2.3"
  register "6.2.2.4" L2 cis_6_2_2_4 "CIS 6.2.2.4"
  register "6.2.3.1" L2 cis_6_2_3_1 "CIS 6.2.3.1"
  register "6.2.3.2" L2 cis_6_2_3_2 "CIS 6.2.3.2"
  register "6.2.3.3" L2 cis_6_2_3_3 "CIS 6.2.3.3"
  register "6.2.3.4" L2 cis_6_2_3_4 "CIS 6.2.3.4"
  register "6.2.3.5" L2 cis_6_2_3_5 "CIS 6.2.3.5"
  register "6.2.3.6" L2 cis_6_2_3_6 "CIS 6.2.3.6"
  register "6.2.3.7" L2 cis_6_2_3_7 "CIS 6.2.3.7"
  register "6.2.3.8" L2 cis_6_2_3_8 "CIS 6.2.3.8"
  register "6.2.3.9" L2 cis_6_2_3_9 "CIS 6.2.3.9"
  register "6.2.3.10" L2 cis_6_2_3_10 "CIS 6.2.3.10"
  register "6.2.3.11" L2 cis_6_2_3_11 "CIS 6.2.3.11"
  register "6.2.3.12" L2 cis_6_2_3_12 "CIS 6.2.3.12"
  register "6.2.3.13" L2 cis_6_2_3_13 "CIS 6.2.3.13"
  register "6.2.3.14" L2 cis_6_2_3_14 "CIS 6.2.3.14"
  register "6.2.3.15" L2 cis_6_2_3_15 "CIS 6.2.3.15"
  register "6.2.3.16" L2 cis_6_2_3_16 "CIS 6.2.3.16"
  register "6.2.3.17" L2 cis_6_2_3_17 "CIS 6.2.3.17"
  register "6.2.3.18" L2 cis_6_2_3_18 "CIS 6.2.3.18"
  register "6.2.3.19" L2 cis_6_2_3_19 "CIS 6.2.3.19"
  register "6.2.3.20" L2 cis_6_2_3_20 "CIS 6.2.3.20"
  register "6.2.3.21" L2 cis_6_2_3_21 "CIS 6.2.3.21"
  register "6.2.4.1" L2 cis_6_2_4_1 "CIS 6.2.4.1"
  register "6.2.4.2" L2 cis_6_2_4_2 "CIS 6.2.4.2"
  register "6.2.4.3" L2 cis_6_2_4_3 "CIS 6.2.4.3"
  register "6.2.4.4" L2 cis_6_2_4_4 "CIS 6.2.4.4"
  register "6.2.4.5" L2 cis_6_2_4_5 "CIS 6.2.4.5"
  register "6.2.4.6" L2 cis_6_2_4_6 "CIS 6.2.4.6"
  register "6.2.4.7" L2 cis_6_2_4_7 "CIS 6.2.4.7"
  register "6.2.4.8" L2 cis_6_2_4_8 "CIS 6.2.4.8"
  register "6.2.4.9" L2 cis_6_2_4_9 "CIS 6.2.4.9"
  register "6.2.4.10" L2 cis_6_2_4_10 "CIS 6.2.4.10"
  register "6.3.1" L2 cis_6_3_1 "CIS 6.3.1"
  register "6.3.2" L2 cis_6_3_2 "CIS 6.3.2"
  register "6.3.3" L2 cis_6_3_3 "CIS 6.3.3"
  register "7.1.1" L1 cis_7_1_1 "CIS 7.1.1"
  register "7.1.2" L1 cis_7_1_2 "CIS 7.1.2"
  register "7.1.3" L1 cis_7_1_3 "CIS 7.1.3"
  register "7.1.4" L1 cis_7_1_4 "CIS 7.1.4"
  register "7.1.5" L1 cis_7_1_5 "CIS 7.1.5"
  register "7.1.6" L1 cis_7_1_6 "CIS 7.1.6"
  register "7.1.7" L1 cis_7_1_7 "CIS 7.1.7"
  register "7.1.8" L1 cis_7_1_8 "CIS 7.1.8"
  register "7.1.9" L1 cis_7_1_9 "CIS 7.1.9"
  register "7.1.10" L1 cis_7_1_10 "CIS 7.1.10"
  register "7.1.11" L1 cis_7_1_11 "CIS 7.1.11"
  register "7.1.12" L1 cis_7_1_12 "CIS 7.1.12"
  register "7.1.13" L1 cis_7_1_13 "CIS 7.1.13"
  register "7.2.1" L1 cis_7_2_1 "CIS 7.2.1"
  register "7.2.2" L1 cis_7_2_2 "CIS 7.2.2"
  register "7.2.3" L1 cis_7_2_3 "CIS 7.2.3"
  register "7.2.4" L1 cis_7_2_4 "CIS 7.2.4"
  register "7.2.5" L1 cis_7_2_5 "CIS 7.2.5"
  register "7.2.6" L1 cis_7_2_6 "CIS 7.2.6"
  register "7.2.7" L1 cis_7_2_7 "CIS 7.2.7"
  register "7.2.8" L1 cis_7_2_8 "CIS 7.2.8"
  register "7.2.9" L1 cis_7_2_9 "CIS 7.2.9"
  register "7.2.10" L1 cis_7_2_10 "CIS 7.2.10"
}


preparse_log() {
  local prev="" arg
  for arg in "$@"; do
    if [[ "$prev" == "--log-file" && -n "$arg" ]]; then
      LOG_FILE="$arg"
    fi
    case "$arg" in
      --color) USE_COLOR=1 ;;
      --no-color) USE_COLOR=0 ;;
      --force) FORCE_OS=1 ;;
    esac
    prev="$arg"
  done
}

main() {
  preparse_log "$@"
  init_logging
  resolve_color
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  trap 'on_exit' EXIT
  parse_args "$@"
  resolve_color
  register_all
  if [[ "$LIST_ONLY" == 1 ]]; then
    local id
    emit INFO "ID LEVEL FUNCTION TITLE"
    for id in "${CONTROL_ORDER[@]}"; do
      emit INFO "${id} ${CONTROL_LEVEL[$id]} ${CONTROL_FUNC[$id]} ${CONTROL_DESC[$id]}"
    done
    NORMAL_EXIT=1
    exit 0
  fi
  if [[ "$ONLY_MODE" == 1 ]]; then
    local wanted
    for wanted in "${!ONLY_SET[@]}"; do
      if [[ -z "${CONTROL_FUNC[$wanted]:-}" ]]; then
        die "unknown recommendation id: ${wanted}" 2
      fi
    done
  fi
  if [[ "$DRY_RUN" != 1 && "$(id -u)" -ne 0 ]]; then
    die "Run as root. Use --dry-run or --list without root." 1
  fi
  validate_policy
  acquire_lock
  init_results
  preflight
  if [[ "$DRY_RUN" != 1 ]]; then
    BACKUP_DIR="/var/backups/cis-mint22-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    emit INFO "backup directory: ${BACKUP_DIR}"
  fi
  emit INFO "======== run ${RUN_ID} user=$(id -un) host=$(hostname 2>/dev/null || echo unknown) ======"
  emit INFO "script: ${SCRIPT_DIR}/$(basename "$0")"
  emit INFO "log file: ${LOG_FILE}"
  emit INFO "results file: ${RESULTS_FILE}"
  emit INFO "color: $([[ "$USE_COLOR" == 1 ]] && echo 'on (green=success, red=error, yellow=info)' || echo off)"
  emit INFO "arguments: ${*:-<none>}"
  emit INFO "Level=$([[ "$APPLY_L2" == 1 ]] && echo '1+2' || echo 1) dry-run=${DRY_RUN} SSH_ACTION=${SSH_ACTION} UFW_ENABLE=${UFW_ENABLE} DISABLE_IPV6=${DISABLE_IPV6} APPLY_UPDATES=${APPLY_UPDATES} APT_UPDATE=${APT_UPDATE}"
  emit INFO "network policy: IPv6 disabled=${DISABLE_IPV6}; ip_forward will be set to 0; net.ipv4.tcp_syncookies will be set to 0 (CIS 3.3.10 wants 1)"
  emit INFO "mount policy: /tmp /var/tmp /home /var /var/log/audit are NOT-NEEDED when they are not already separate mounts. No filesystem is created for them. /var/log stays MANUAL. /dev/shm is still hardened."
  if [[ "$APPLY_UPDATES" == 1 ]]; then
    emit WARN "HIGH IMPACT if this is not a dry-run: apt-get update and apt-get upgrade; AppArmor enforce; IPv6 off; forwarding off; SYN cookies off; /dev/shm noexec; UFW; SSH_ACTION=${SSH_ACTION}; mintupdate; password length ${PW_MINLEN}; TMOUT ${TMOUT_SECONDS}; su limited to empty group ${SU_GROUP}."
  else
    emit WARN "HIGH IMPACT if this is not a dry-run: apt-get upgrade is OFF (--no-apply-updates); AppArmor enforce; IPv6 off; forwarding off; SYN cookies off; /dev/shm noexec; UFW; SSH_ACTION=${SSH_ACTION}; mintupdate; password length ${PW_MINLEN}; TMOUT ${TMOUT_SECONDS}; su limited to empty group ${SU_GROUP}."
  fi
  if [[ "$APPLY_L2" == 1 ]]; then
    emit WARN "LEVEL 2: usb-storage/squashfs/overlay/udf; CUPS=${CUPS_ACTION}; bluetooth=${BLUETOOTH_ACTION}; avahi=${AVAHI_ACTION}; NOPASSWD commented; password aging; auditd halt-on-full; AIDE init=${AIDE_INIT}; audit immutable=${AUDIT_IMMUTABLE}."
  fi
  local id level fn rc start end status note ok0 fail0 man0 skip0 nn0
  for id in "${CONTROL_ORDER[@]}"; do
    if [[ "$ONLY_MODE" == 1 && -z "${ONLY_SET[$id]:-}" ]]; then
      continue
    fi
    level="${CONTROL_LEVEL[$id]}"
    fn="${CONTROL_FUNC[$id]}"
    if [[ "$level" == "L2" && "$APPLY_L2" != 1 ]]; then
      skip "${id} Level 2 is off. Re-run with --level2."
      write_result "$id" "$level" "SKIP" "0" "Level 2 is off"
      continue
    fi
    if ! declare -F "$fn" >/dev/null 2>&1; then
      fail "${id} function ${fn} is not defined"
      write_result "$id" "$level" "FAIL" "0" "function missing"
      continue
    fi
    CURRENT_ID="$id"
    emit INFO "BEGIN ${id} [${level}] ${fn}"
    ok0=$N_OK; fail0=$N_FAIL; man0=$N_MANUAL; skip0=$N_SKIP; nn0=$N_NOTNEEDED
    start="$(date +%s)"
    set +e
    "$fn"
    rc=$?
    set +e
    end="$(date +%s)"
    if [[ "$rc" -ne 0 ]]; then
      fail "${id} ${fn} returned ${rc} after $((end - start))s"
    fi
    if (( N_FAIL > fail0 )); then
      status="FAIL"
      note="${FAIL_NOTES[-1]}"
    elif (( N_MANUAL > man0 )); then
      status="MANUAL"
      note="${MANUAL_NOTES[-1]}"
    elif (( N_NOTNEEDED > nn0 )); then
      status="NOT-NEEDED"
      note="${NOTNEEDED_NOTES[-1]}"
    elif (( N_SKIP > skip0 )); then
      status="SKIP"
      note="${CONTROL_DESC[$id]}"
    else
      status="OK"
      note="${CONTROL_DESC[$id]}"
    fi
    write_result "$id" "$level" "$status" "$((end - start))" "$note"
    emit INFO "END ${id} status=${status} function_rc=${rc} elapsed=$((end - start))s cumulative ok=${N_OK} skip=${N_SKIP} not_needed=${N_NOTNEEDED} manual=${N_MANUAL} fail=${N_FAIL} command_errors=${N_CMD_FAIL}"
    CURRENT_ID=""
  done
  CURRENT_ID=""
  finalize_grub
  if [[ "$DRY_RUN" != 1 ]]; then
    run_cmd sysctl --system || warn "final sysctl --system returned non-zero"
    if [[ -f /boot/grub/grub.cfg ]]; then
      if chown root:root /boot/grub/grub.cfg && chmod u-x,go-rwx /boot/grub/grub.cfg; then
        emit OK "restored /boot/grub/grub.cfg to mode 0600 root:root"
      else
        fail "could not chmod /boot/grub/grub.cfg to 0600"
      fi
    fi
  else
    emit DRY-RUN "would run sysctl --system and restore grub.cfg mode 0600 after update-grub"
  fi
  emit INFO "======== summary run ${RUN_ID} ========"
  emit OK "controls passed: ${N_OK}"
  emit SKIP "controls skipped: ${N_SKIP}"
  emit NOT-NEEDED "controls not needed (mount not separate): ${N_NOTNEEDED}"
  emit MANUAL "controls needing a person: ${N_MANUAL}"
  if [[ "$N_FAIL" -gt 0 ]]; then
    emit FAIL "controls failed: ${N_FAIL}"
  else
    emit OK "controls failed: 0"
  fi
  if [[ "$N_CMD_FAIL" -gt 0 ]]; then
    emit ERROR "commands that returned non-zero: ${N_CMD_FAIL} (see ERROR lines; stopping a unit that is already absent is expected)"
  else
    emit OK "commands that returned non-zero: 0"
  fi
  emit INFO "======== reboot checklist ========"
  if ((${#REBOOT_REASONS[@]})); then
    local reason
    for reason in "${REBOOT_REASONS[@]}"; do
      emit WARN "  - ${reason}"
    done
  else
    emit INFO "no reboot-required change was recorded by this run"
  fi
  emit INFO "======== failures ========"
  if ((${#FAIL_NOTES[@]})); then
    local item
    for item in "${FAIL_NOTES[@]}"; do
      emit FAIL "  ${item}"
    done
  else
    emit OK "no failures"
  fi
  emit INFO "======== not needed (mount was not separate) ========"
  if ((${#NOTNEEDED_NOTES[@]})); then
    local item
    for item in "${NOTNEEDED_NOTES[@]}"; do
      emit NOT-NEEDED "  ${item}"
    done
  else
    emit INFO "no not-needed mount controls"
  fi
  emit INFO "======== still needs a person ========"
  if ((${#MANUAL_NOTES[@]})); then
    local item
    for item in "${MANUAL_NOTES[@]}"; do
      emit MANUAL "  ${item}"
    done
  else
    emit INFO "no manual follow-ups"
  fi
  emit INFO "log file: ${LOG_FILE}"
  emit INFO "results file: ${RESULTS_FILE}"
  emit INFO "This script is not a CIS certified build kit. Confirm every MANUAL line before an audit. NOT-NEEDED means that mount was not separate and was ignored on purpose. tcp_syncookies=0 fails CIS 3.3.10 on purpose."
  NORMAL_EXIT=1
  if [[ "$N_FAIL" -gt 0 ]]; then
    exit 1
  fi
}

main "$@"

