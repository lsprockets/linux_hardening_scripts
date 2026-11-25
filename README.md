# linux_hardening_scripts

## Download on a new machine

The repository is public. No login.

```bash
curl -fsSL -O https://raw.githubusercontent.com/lsprockets/linux_hardening_scripts/main/cis-linux-mint-22-harden.sh
chmod 755 cis-linux-mint-22-harden.sh
```

Or, if you only have git:

```bash
curl -fsSL -O https://raw.githubusercontent.com/lsprockets/linux_hardening_scripts/main/get-cis-mint22.sh
bash get-cis-mint22.sh
```

`get-cis-mint22.sh` downloads every root `.sh` file except `get-cis*.sh`. Right now that list is only `cis-linux-mint-22-harden.sh`. It uses curl or wget, and falls back to `git clone` when those are missing.

Operator scripts for hardening Linux hosts. These are not CIS certified build kits. A passing run is not a certified score. Snapshot the machine before the first real run.

## cis-linux-mint-22-harden.sh

Workstation remediation for CIS Linux Mint 22 Benchmark v1.0.0. Level 1 runs by default. Level 2 is `--level2`.

```bash
sudo ./cis-linux-mint-22-harden.sh --dry-run
sudo ./cis-linux-mint-22-harden.sh
sudo ./cis-linux-mint-22-harden.sh --level2
./cis-linux-mint-22-harden.sh --help
```

Site choices baked into this copy:

- IPv6 is disabled (`net.ipv6.conf.all/default/lo.disable_ipv6=1`). `--keep-ipv6` leaves it on.
- IP forwarding is set to 0 for IPv4 and IPv6.
- `net.ipv4.tcp_syncookies` is set to 0. CIS 3.3.10 wants 1. A benchmark audit of that item will fail until it is set back.
- Enabled apt sources are checked against official Linux Mint 22 (wilma, xia, zara, zena) and Ubuntu noble archives. Non-official lines are reported and left in place.
- If `/tmp`, `/var/tmp`, `/home`, `/var`, or `/var/log/audit` is not already its own mount, those recommendations are `NOT-NEEDED`. No partition is created.

A normal run also does `apt-get update` and `apt-get upgrade` (not dist-upgrade). `--no-apply-updates` skips the upgrade. `--no-apt-update` skips the index refresh.

`cis-mint22-harden.lock` exists only while a run is in progress. The script deletes it on exit, including failure and Ctrl-C. A leftover file means the last run was killed with SIGKILL.

Every run also creates user `iamthebrain` (uid 2345, private group gid 2345) in group `wheel`. `/etc/sudoers.d/90-iamthebrain` lets that user sudo with no password. The login password is left locked; set it with `passwd iamthebrain`. Level 2 does not delete that sudoers file.

Logs go to `cis-mint22-harden.log` next to the script. Each line is timestamped. On a terminal, OK is green, FAIL/ERROR is red, and everything else is yellow.
