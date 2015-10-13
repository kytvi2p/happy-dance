#!/bin/sh

###
# happy-dance.sh by _NSAKEY
# Requirements: OpenSSH 6.5 or above, sudo access.
# (But you should probably run as root anyway)
#
# This script automates everything laid out in stribika's Secure Secure Shell.
# Source: https://stribika.github.io/2015/01/04/secure-secure-shell.html
#
# Tested on the following platforms:
# - Debian Wheezy & Jessie (With ssh from wheezy-backports for Wheezy)
# - Ubuntu 14.04 & 15.04 (12.04 will work with a PPA according to https://github.com/NSAKEY/happy-dance/issues/1#issuecomment-128469412)
# - CentOS 7
# - Mac OS X Yosemite Niresh with Homebrew's openssh
# - FreeBSD 10 & 11
# - OpenBSD 5.7
# - NetBSD 7.0
# - Solaris 11.2 with CSWOpenSSH and 11.3 Beta with OpenSSH from the package manager

# Notes:
# 1. OpenBSD/NetBSD users: /etc/moduli is the same as /etc/ssh/moduli on other
# platforms. You don't have to do anything extra to make the script work.
# Also, SHA256 fingerprints are now a thing for you.
#
# 2. Mac users: You need to install Homebrew. Once that's done, install openssh like so:
# "brew tap homebrew/dupes"
# "brew install openssh --with-brewed-openssl"
# This will give you a working version of OpenSSH with OpenSSL. Testing without
# OpenSSL failed miserably, so installing it is required.
#
# 3. Another Mac user note: The script drops "unset SSH_AUTH_SOCK" in your
# .bash_profile. This is needed so that you can connect to remote hosts. Check the
# comments below if you wish to know more.
#
# 4. Solaris users: The 11.3 beta has OpenSSH 6.5 in the package manager, but it's the only
# version of 6.5 I've ever seen that does NOT support ED25519 keys. It does, however, support
# the -o flag introduced in OpenSSH 6.5, so that's now used for the version check code.
# my process for switching to Oracle's OpenSSH, because they may add ED25519 support one day.
# The "OpenSSH in Solaris 11.3" blog post by Darren Moffat
# (Found here: https://blogs.oracle.com/darren/entry/openssh_in_solaris_11_3)
# states that both SunSSH and OpenSSH can be installed side by side. My experience is that
# if SunSSH is installed, it takes precedence over OpenSSH, and the only way I found around
# it is to uninstall SunSSH. I don't use Solaris daily (And only ported happy-dance to it for fun),
# so I'm certain there's a way to switch without uninstalling ssh. Suggestions are welcome.
#
# TO DO:
# 1. Windows 10 support?
###

set -eu
# pretty colors
echo_green() { printf "\033[0;32m$1\033[0;39;49m\n"; }
echo_red() { printf "\033[0;31m$1\033[0;39;49m"; }

# Just setting some variables before we start.
HAPPYTMP="$(mktemp -d /tmp/HAPPY.XXXXXX)"
trap 'rm -rf $HAPPYTMP' 0 1 2 15
UNAME=$(uname -s)
# Solaris 11.3's OpenSSH does not support ED25519 keys (Source:
# https://twitter.com/darrenmoffat/status/641568090581528576), but does support
# the option to use bcrypt to protect keys at rest. Since that option is
# common to all newer implementations of OpenSSH, that's what will be used for
# the version check from now on.
VERSION=`ssh-keygen -t rsa -f "${HAPPYTMP}/version.check" -o -a 100 -q -N "" < /dev/null 2> /dev/null; echo $?`

# Constants
MACs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com"
KexAlgorithms="curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
Ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
HostKeyAlgorithms="ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa"

# What follows is just some introductory text.
help() {
printf "This script will give you ssh configs for clients and servers\nwhich should force the NSA to work for a living.

For an explanation of everything used in the configs, check out Secure Secure Shell:
https://stribika.github.io/2015/01/04/secure-secure-shell.html
Check out the README and the script's source if you want to see how the sausage is made.

Flags:
            -c  Set up a client. Use this if you're hardening your user config
                to make connections to remote hosts.
            -s  Set up a server. Use this flag if you're hardening the ssh config
                of a remote host to accept connections from users.

NOTE: Setting up a user config will require sudo or root access to give you a
new ssh_config file.

"
}

# Before getting too carried away, we're going to check the SSH version in an
# informal but clear way. This script requires OpenSSH 6.5, so generating a
# test RSA key with the -o flag is the quickest and easiest way to do a version check.

if [ $VERSION -gt 0 ]; then
    echo_red "Your OpenSSH version is too old to run happy-dance. Upgrade to 6.5 or above.\n"
    exit 1
fi

check_for_root() {
        if [ $(id -u) -ne 0 ]; then
                echo_red "This option must be run as root.\n"
                exit 1
        fi
}

freebsd_disable_insecure_key_types() {
        local insecure='
                sshd_rsa1_enable
                sshd_dsa_enable
                sshd_ecdsa_enable
                '
        for each in $insecure; do
                if grep -q $each /etc/rc.conf; then
                        sed -I.bak "s/\($each\).*/\1=\"NO\"/" /etc/rc.conf
                else
                        printf "%s=\"NO\"\n" $each >> /etc/rc.conf
                fi
        done
}

generate_host_ssh_keys() {
        ssh_path="$1"

        modify_sshd_config "${ssh_path}"
        rm -f ${ssh_path}/ssh_host_*key* > /dev/null 2>&1 || true
        ssh-keygen -t ed25519 -f ${ssh_path}/ssh_host_ed25519_key -q -N "" < /dev/null 2> /dev/null
        ssh-keygen -t rsa -b 4096 -f ${ssh_path}/ssh_host_rsa_key -q -N "" < /dev/null
        case $UNAME in
                FreeBSD)
                        freebsd_disable_insecure_key_types
                        ;;
                NetBSD|OpenBSD)
                        net_and_openbsd_disable_insecure_key_types "${ssh_path}"
                        ;;
        esac
        ED25519_fingerprint="$(ssh-keygen -l -f ${ssh_path}/ssh_host_ed25519_key.pub 2> /dev/null)"
        RSA_fingerprint="$(ssh-keygen -l -f ${ssh_path}/ssh_host_rsa_key.pub)"
        ED25519_fingerprint_MD5="$(ssh-keygen -l -E md5 -f ${ssh_path}/ssh_host_ed25519_key.pub 2> /dev/null || true)"
        RSA_fingerprint_MD5="$(ssh-keygen -l -E md5 -f ${ssh_path}/ssh_host_rsa_key.pub 2> /dev/null || true)"
}

generate_moduli() {
        case $UNAME in
                OpenBSD|NetBSD)
                        moduli_path="/etc/moduli"
                        ;;
                *)
                        moduli_path="$1"
                        ;;
        esac
        echo_red "Your OS doesn't have an $moduli_path file, so we have to generate one. This might take a while.\n"
        ssh-keygen -G "${HAPPYTMP}/moduli.all" -b 4096
        ssh-keygen -T "${moduli_path}" -f "${HAPPYTMP}/moduli.all"
}

modify_ssh_config() {
        ssh_config="${1}"

        # Backup before changing anything
        [ -f "${ssh_config}" ] && cp "${ssh_config}" "${ssh_config}.bak"

        if grep -Eq '^.*Host \*$' "${ssh_config}" 2>/dev/null ; then
                sed_i 's/^.*Host \*$/Host */' "${ssh_config}"
        else
                printf 'Host *\n' >> "${ssh_config}"
        fi

        set_config_option "${ssh_config}" "ChallengeResponseAuthentication" "no"

        set_config_option "${ssh_config}" 'PasswordAuthentication' 'no'

        set_config_option "${ssh_config}" 'PubkeyAuthentication' 'yes'

        set_config_option "${ssh_config}"  'MACs' "${MACs}"

        set_config_option "${ssh_config}" 'Ciphers' "${Ciphers}"

        set_config_option "${ssh_config}" 'HostKeyAlgorithms' "${HostKeyAlgorithms}"

        set_config_option "${ssh_config}" 'KexAlgorithms' "${KexAlgorithms}"
}

modify_sshd_config() {
        ssh_path="$1"
        sshd_config="${ssh_path}/sshd_config"

        # Make a backup before making any changes
        cp "${sshd_config}" "${sshd_config}.bak"

        # Remove weak keys from the config file
        sed_i 's;^\(Host.*dsa.*\|Host.*host_key$\);#\1;' "${sshd_config}"

        # Add keys if missing from the config file
        if ! grep -q '^HostKey.*ed25519_key$' "${sshd_config}"; then
                printf "HostKey %s/ssh_host_ed25519_key\n" ${ssh_path} >> "${sshd_config}"
        fi
        if ! grep -q '^HostKey.*rsa_key$' "${sshd_config}"; then
                printf "HostKey %s/ssh_host_rsa_key\n" ${ssh_path} >> "${sshd_config}"
        fi

        set_config_option "${sshd_config}" 'MACs' "${MACs}"

        set_config_option "${sshd_config}" 'Ciphers' "${Ciphers}"

        set_config_option "${sshd_config}" 'KexAlgorithms' "${KexAlgorithms}"
}

modify_moduli() {
        moduli_path="$1"
        echo_green "Modifying your $moduli_path\n"
        awk '$5 > 2000' "$moduli_path" > "${HAPPYTMP}/moduli"
        mv "${HAPPYTMP}/moduli" "$moduli_path"
}

net_and_openbsd_disable_insecure_key_types() {
        # Better way wanted!
        sshd_path="${1}"
        echo_green "Symlinking ${sshd_path}/ssh_host_*dsa_key \nand ${sshd_path}/ssh_host_key to /dev/null\n" >&2
        local unwanted='
            ssh_host_key
            ssh_host_dsa_key
            ssh_host_ecdsa_key
        '
        for each in $unwanted; do
                ln -s /dev/null $sshd_path/$each
        done

        if [ $UNAME = 'NetBSD' ]; then
                echo_red 'Preventing NetBSD from generating unwanted keys at boot...\n'
                # NetBSD's sed supports -i natively, so let's not use the wrapped version
                sed -i -e 's/\(\s*run_rc_command keygen\)/#\1/' /etc/rc.d/sshd
        fi
}

print_for_solaris_users() {
        echo_green "\nSolaris 11.2 and older users need to install OpenSSH from OpenCSW in order for happy-dance to work."
        echo_green "Solaris 11.3 users can get OpenSSH by running the following commands:\n"
        echo_red "pkg uninstall ssh\n"
        echo_red "pkg install openssh\n"
        echo_green "You can verify the ssh version before and after by running 'pkg mediator ssh'"
        echo_green "and looking at the 'IMPLEMENTATION' column or by running 'ssh -V' and reading the output.\n"
}

sed_i() {
        # Even in the year 2015 not all versions of sed support in-line editing :/
        sed -e "${1}" "${2}" > $HAPPYTMP/sed.out
        mv "$HAPPYTMP/sed.out" "$2"
}

set_config_option() {
        local file="${1}"
        local key="${2}"
        local value="${3}"
        if $(echo $file |grep -q 'sshd_config'); then
                local tab=''
        else
                local tab='     '
        fi
        if grep -q ".*${key}" "${file}"; then
                sed_i "s/^.*${key}.*$/${tab}${key} ${value}/" "${file}"
        else
                echo "${tab}${key} ${value}" >> "${file}"
        fi
}

# The ssh_client function takes the time to check for the existence of keys
# because deleting or overwriting existing keys would be bad.
ssh_client() {
        echo_green "This option updates your ssh_config after backing up the original.\n"
        echo_red "Are you sure you want to proceed? (y/n) "
        read yn
        case $yn in
                [Yy]*) echo_green "Updating your ssh client configuration file..\n"
                        ;;
                *)
                        exit
                        ;;
        esac

        if [ $(id -u) -eq 0 ]; then
                echo_green 'Root access detected, editing global client configs'

                if [ -f /usr/local/etc/ssh/ssh_config ]; then
                        modify_ssh_config /usr/local/etc/ssh/ssh_config
                else
                        modify_ssh_config /etc/ssh/ssh_config
                fi
                [ -d /root/.ssh ] || mkdir -m700 /root/.ssh
                modify_ssh_config /root/.ssh/config
        else
                echo_green 'Non-root user detected, will update user client configs.'
                [ -d $HOME/.ssh ] || mkdir -m700 $HOME/.ssh
                modify_ssh_config $HOME/.ssh/config
                echo_red 'To update the system client configs, re-run\n'
                echo_red 'this command as root or with sudo.\n'
        fi

        if [ $(logname) != $LOGNAME ]; then
                # script is being run with sudo. Re-set HOME accordingly
                REALHOME="$(getent passwd $(logname) | awk -F: '{print $6}')"
        else
                REALHOME=$HOME
        fi

        # If you don't already have ssh keys, they will be generated for you.
        # If you do have keys, they won't be deleted, because that would be rude.
        [ -f $REALHOME/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -f "$REALHOME/.ssh/id_ed25519" -C "$(logname)@$(hostname)" -o -a 100

        if [ ! -f $REALHOME/.ssh/id_rsa ]; then
                ssh-keygen -t rsa -f "$REALHOME/.ssh/id_rsa" -b 4096 -C "$(logname)@$(hostname)" -o -a 100
        else
                KEYSIZE=$(ssh-keygen -l -f $REALHOME/.ssh/id_rsa.pub | awk '{print $1}')
                if [ "$KEYSIZE" -ne 4096 ]; then
                        echo_red "You already have an RSA key but it's only $KEYSIZE bits long.\n"
                        echo_red "You should delete or move it and re-run this script, or generate another key by hand!\n"
                        echo_red "The command to generate your own RSA key pair is:\n"
                        echo_red "     ssh-keygen -t rsa -b 4096 -o -a 100\n"
                fi
        fi
        chown $(logname) $REALHOME/.ssh/id_rsa* $REALHOME/.ssh/id_ed25519*

        # Just printing some info for Solaris users.

        if [ $UNAME = "SunOS" ]; then
                print_for_solaris_users
        elif [ $UNAME = "Darwin" ]; then
                # This rather hackish check for OS X is only done so that the
                # user's .bash_profile can be modified to make outgoing ssh
                # connections work.
                if grep -qFx "unset SSH_AUTH_SOCK" ~/.bash_profile; then
                        # This just keeps the user from having SSH_AUTH_SOCK
                        # unset multiple times. It's a matter of config file
                        # cleanliness.
                        echo_red "Refusing to duplicate effort in your .bash_profile\n"
                else
                        printf "unset SSH_AUTH_SOCK\n" >> ~/.bash_profile
                fi
                echo_green "Since you use Mac OS X, you had to have a small modification to your .bash_profile"
                echo_green "in order to connect to remote hosts. Read here and follow the links to learn more: http:/serverfault.com/a/486048\n"
                echo_green "OpenSSH will work the next time you log in. If you want to use OpenSSH imediately, run the following command in your terminal:"
                echo_green "unset SSH_SOCK_AUTH"
                echo_green "You only have to run that command once. That line is in your .bash_profile\n and will automatically make OpenSSH work for you on all future logins.\n"
        fi
        exit 0
}

# Meanwhile, the ssh_server function asks if you're sure you want to
# obliterate the public/private keypairs which make up the host keys.
# After that, /etc/ssh/moduli is either hardened or generated in a hardened
# state and then the ED25519 and 4096-bit RSA host keys are generated. As
# having passwords on host keys means that sshd won't start automatically,
# the choice of passwording them has been removed from the user.

ssh_server() {
        echo_green "This option destroys all host keys and updates your sshd_config file."
        echo_red "Are you sure want to proceed? (y/n) "
        read yn
        case $yn in
                [Yy]*) echo_green "Updating your ssh server configuration file.."
                        ;;
                *)
                        exit
                        ;;
        esac

        # Some platforms (Such as OpenBSD and NetBSD) store the moduli in /etc/moduli,
        # instead of /etc/ssh/moduli.

        if [ -s /etc/ssh/moduli ]; then
                modify_moduli /etc/ssh/moduli
        elif [ -s /etc/moduli ]; then
                modify_moduli /etc/moduli
        elif [ -d /etc/ssh ]; then
                generate_moduli /etc/ssh/moduli
        else
                generate_moduli /etc/moduli
        fi

        # Some platforms stuff the ssh config files under /usr/local, and this is also
        # the case if you've built your own ssh binary. So instead of doing $UNAME checks,
        # I just opted to check whether /usr/local/etc/ssh exists. I have yet to find a
        # scenario in which one of these two dir paths aren't used, so there is no
        # baked in error handling if /usr/local/etc/ssh and /etc/ssh don't exist.

        # As for what the branches in the if do, they each copy over the hardened config,
        # rm the host key files, generate new keys, then store those keys in variables
        # for printing later. You should always verify host key fingerprints,
        # and you are more likely to do it if this script makes it easy for you.
        # The variables are set up so that if you're using OpenSSH 6.5-6-7, the script
        # will print just the MD5 fingerprints. If you're using OpenSSH 6.8 and above,
        # it will print both the MD5 and SHA256 fingerprints. This means you can
        # easily verify the key fingerprints on your next login without having to
        # worry about your OpenSSH version.

        if [ -d /usr/local/etc/ssh ]; then
                generate_host_ssh_keys "/usr/local/etc/ssh"
        else
                generate_host_ssh_keys "/etc/ssh"
        fi

        # This next bit of code just prints the key fingerprints. if the *_MD5
        # variables contain anything at all, they will print. Otherwise, that's
        # 2 fewer lines printed in your terminal.

        echo_green "Your new host key fingerprints are:"
        printf "$ED25519_fingerprint\n" 2> /dev/null
        printf "$RSA_fingerprint\n"
        if [ -n "$ED25519_fingerprint_MD5" ]; then
                printf "$ED25519_fingerprint_MD5\n" 2> /dev/null
        fi

        if [ -n "$RSA_fingerprint_MD5" ]; then
                printf "$RSA_fingerprint_MD5\n"
        fi
        echo_green "Don't forget to verify these!\n"

        if [ $UNAME = "SunOS" ]; then
                print_for_solaris_users
        else
                echo_green "Without closing this ssh session, do the following:
                1. Add your public key to ~/.ssh/authorized_keys if it isn't there already
                2. Restart your sshd.
                3. Remove the line from the ~/.ssh/known_hosts file on your computer which corresponds to this server.
                4. Try logging in. If it works, HAPPY DANCE!\n"
        fi
        exit 0
}

# This last bit of code just defines the flags.
while getopts "cs" opt; do
    case $opt in

        c)
            ssh_client
        ;;

        s)
            check_for_root && ssh_server
        ;;
    esac
done
help # only displayed if no parameters were specified
