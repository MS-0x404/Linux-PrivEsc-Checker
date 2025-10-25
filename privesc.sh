#!/bin/bash
####
#### Authors: https://github.com/MS-0x404
#### Version: 1.0 

# Global Variables
readonly -a cap_ignore_list=(
    "snap-confine"
    "sssd_pam"
    "krb5_child"
    "ldap_child"
    "selinux_child"
    "gst-ptp-helper"
)
readonly -a binari_sospetti=(
    "aa-exec" "ab" "agetty" "alpine" "ar" "arj" "arp" "as" "ash" "ascii-xfr"
    "aspell" "atobm" "awk" "base32" "base64" "basenc" "basez" "bash" "bc"
    "bridge" "busctl" "busybox" "bzip2" "cabal" "capsh" "cat" "chmod" "choom"
    "chown" "chroot" "clamscan" "cmp" "column" "comm" "cp" "cpio" "cpulimit"
    "csh" "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dd"
    "debugfs" "dialog" "diff" "dig" "distcc" "dmsetup" "docker" "dosbox" "ed"
    "efax" "elvish" "emacs" "env" "eqn" "espeak" "expand" "expect" "file"
    "find" "fish" "flock" "fmt" "fold" "gawk" "gcore" "gdb" "genie" "genisoimage"
    "gimp" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3"
    "iconv" "install" "ionice" "ip" "ispell" "jjs" "join" "jq" "jrunscript"
    "julia" "ksh" "ksshell" "kubectl" "ld.so" "less" "links" "logsave" "look"
    "lua" "make" "mawk" "minicom" "more" "mosquitto" "msgattrib" "msgcat"
    "msgconv" "msgfilter" "msgmerge" "msguniq" "multitime" "mv" "nasm" "nawk"
    "ncftp" "nft" "nice" "nl" "nm" "nmap" "node" "nohup" "ntpdate" "od"
    "openssl" "openvpn" "pandoc" "paste" "perf" "perl" "pexec" "pg" "php"
    "pidstat" "pr" "ptx" "python" "rc" "readelf" "restic" "rev" "rlwrap"
    "rsync" "rtorrent" "run-parts" "rview" "rvim" "sash" "scanmem" "sed"
    "setarch" "setfacl" "setlock" "shuf" "soelim" "softlimit" "sort" "sqlite3"
    "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass" "start-stop-daemon"
    "stdbuf" "strace" "strings" "sysctl" "systemctl" "tac" "tail" "taskset"
    "tbl" "tclsh" "tee" "terraform" "tftp" "tic" "time" "timeout" "troff" "ul"
    "unexpand" "uniq" "unshare" "unsquashfs" "unzip" "update-alternatives"
    "uudecode" "uuencode" "vagrant" "varnishncsa" "view" "vigr" "vim" "vimdiff"
    "vipw" "w3m" "watch" "wc" "wget" "whiptail" "xargs" "xdotool" "xmodmap"
    "xmore" "xxd" "xz" "yash" "zsh" "zsoelim"
)
readonly -a cap_sospetti=(
    "cap_dac_override"
    "cap_dac_read_search"
    "cap_chown"
    "cap_setuid"
    "cap_setgid"
    "cap_fowner"
    "cap_sys_admin"
    "cap_sys_ptrace"
    "cap_mac_override"
    "cap_net_bind_service"
    "cap_sys_rawio"
    "cap_sys_chroot"
)
readonly -a list_ver_sudo=(
    "1.9.14"
    "1.9.15"
    "1.9.16"
)
readonly -a kernel_list=(
    "3.15"
    "6.7.3"
    "5.8"
    "5.16.11"
    "2.6.22"
    "2.6.9"
)


## Logo Ascii 
main_logo() {
cat << 'EOF'
    ________________________________________ 
(                                        )
(  Fry: Feels root, man.                 )
    -------------------------------------------------- 
      o
        o
          o  
             ,'``.._   ,'``.
            :,--._:)\,:,._,.:
            :`--,''@@@:`...';\        
             `,'@@@@@@@`---'@@`.     
             /@@@@@@@@@@@@@@@@@:
            /@@@@@@@@@@@@@@@@@@@\
          ,'@@@@@@@@@@@@@@@@@@@@@:\.___,-.
         `...,---'``````-..._@@@@|:@@@@@@@\
           (                 )@@@;:@@@@)@@@\  _,-.
            `.              (@@@//@@@@@@@@@@`'@@@@\
             :               `.//@@)@@@@@@)@@@@@,@;
             |`.            _,'/@@@@@@@)@@@@)@,'@,'
             :`.`-..____..=:.-':@@@@@.@@@@@_,@@,'
            ,'\ ``--....-)='    `._,@@\    )@@@'``._
           /@_@`.       (@)      /@@@@@)  ; / \ \`-.'
          (@@@`-:`.     `' ___..'@@_,-'   |/   `.)
           `-. `.`.``-----``--,@@.'
             |/`.\`'        ,',');
                 `         (/  (/

    Ricerca Privilege Escalation...

EOF

}

## Controlla eventuali SUID sospetti
suid() {
    local found=0

    local regex_pattern
    regex_pattern=$(printf "%s|" "${binari_sospetti[@]}")
    regex_pattern="(${regex_pattern%|})$" 

    local matches
    matches=$(find / -type f -perm -4000 2>/dev/null | grep -E "$regex_pattern")

    if [[ -n "$matches" ]]; then
        echo "[+] Possibile PrivEsc tramite SUID:"
        echo "$matches" | sed 's/^/  └─ /'
        found=1
    fi

    [[ $found -eq 0 ]] && echo "[-] Nessuna PrivEsc tramite SUID"
}


exports_nfs() {
    local lista
    lista=$(grep "no_root_squash" /etc/exports 2>/dev/null)
    
    if [[ -n "$lista" ]]; then
        echo "[+] Possibile PrivEsc tramite NFS:"
        echo "$lista" | sed 's/^/  └─ /'
    else
        echo "[-] Nessuna PrivEsc tramite NFS"
    fi
}

## Controlla la Capabilities
capabilities() {
    local found=0
    
    local regex_pattern
    regex_pattern=$(printf "%s|" "${cap_sospetti[@]}")
    regex_pattern="(${regex_pattern%|})" 

    local ignore_pattern
    ignore_pattern=$(printf "%s|" "${cap_ignore_list[@]}")
    ignore_pattern="(${ignore_pattern%|})" 

    local matches
    matches=$(getcap -r / 2>/dev/null | grep -E "$regex_pattern" | sort -u | grep -v -E "$ignore_pattern")

    if [[ -n "$matches" ]]; then
        echo "[+] Possibile PrivEsc tramite Capabilities:"
        echo "$matches" | sed 's/^/  └─ /'
        found=1
    fi
    
    [[ $found -eq 0 ]] && echo "[-] Nessuna PrivEsc tramite Capabilities."
}

cron_job() {
    local found=0
    
    local root_jobs
    root_jobs=$(grep -vE '(^#|anacron|^$)' /etc/crontab 2>/dev/null | grep "root")

    if [[ -z "$root_jobs" ]]; then
        echo "[-] Nessuna PrivEsc tramite Crontab"
        return
    fi

    echo "$root_jobs" | while IFS= read -r job_line; do
        local command
        command=$(echo "$job_line" | awk '{ $1=$2=$3=$4=$5=$6=""; print $0 }' | sed 's/^[ \t]*//')

        local paths
        paths=$(echo "$command" | grep -oE '(/[a-zA-Z0-9_.-]+)+')

        if [[ -z "$paths" ]]; then
            continue 
        fi

        echo "$paths" | while IFS= read -r path; do
            if [ -w "$path" ]; then
                if [[ $found -eq 0 ]]; then
                    echo "[+] Possibile PrivEsc tramite Crontab:"
                    found=1
                fi
                echo "  └─ L'utente $USER può scrivere in '$path', che è eseguito da root:"
                echo "     └─ $job_line"
            fi
        done
    done
    
    [[ $found -eq 0 ]] && echo "[-] Nessuna PrivEsc tramite Crontab."
}

# Controlla i permessi sudo e la versione
sudo_esc() {
    local current_sudo_ver
    current_sudo_ver=$(sudo --version | head -n 1 2>/dev/null) 
    local ver_found=0
    
    # Controlla se abbiamo ottenuto una versione
    if [[ -n "$current_sudo_ver" ]]; then
        for ver in "${list_ver_sudo[@]}"; do
            if echo "$current_sudo_ver" | grep -q "$ver"; then
                ver_found=1
                break
            fi
        done
        
        if [[ $ver_found -eq 1 ]]; then
            echo "[+] Trovata versione Sudo potenzialmente VULNERABILE:"
            echo "  └─ $current_sudo_ver"
        else
            echo "[-] Versione di Sudo non Vulnerabile provare:"
            echo "  └─ sudo -l"
        fi
    else
        echo "[-] Impossibile determinare la versione di sudo."
    fi

}

# Controlla la versione del kernel
kernel_priv() {
    local current_kernel
    current_kernel=$(uname -r)
    local ver_found=0

    for ver in "${kernel_list[@]}"; do
        if echo "$current_kernel" | grep -q "$ver"; then
            ver_found=1
            break
        fi
    done

    if [[ $ver_found -eq 1 ]]; then
        echo "[+] Possibile PrivEsc tramite Kernel (versione nota):"
        echo "  └─ $current_kernel"
    else
        echo "[-] Nessuna PrivEsc tramite Kernel"
        echo "  └─ Versione attuale: $current_kernel (controlla manualmente)"
    fi
}

# Main Function
main() {
    # Logo Ascii
    main_logo

    ## Call Function 
    suid
    capabilities
    exports_nfs
    cron_job
    sudo_esc
    kernel_priv
}

## Inizialization
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
