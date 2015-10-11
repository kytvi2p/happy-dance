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
# - NetBSD 7.0 RC 1
# - Solaris 11.2 with CSWOpenSSH and 11.3 Beta with OpenSSH from the package manager

# Notes:
# 1. OpenBSD/NetBSD users: /etc/moduli is the same as /etc/moduli on other
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

# Just setting some variables before we started.

HAPPYTMP="$(mktemp -d /tmp/HAPPY.XXXXXX)"
trap 'rm -rf $HAPPYTMP' 0 1 2 15
UNAME=`uname`
#VERSION=`ssh-keygen -t ed25519 -f /tmp/version.check -o -a 100 -q -N "" < /dev/null 2> /dev/null; echo $?` # Old version check.
VERSION=`ssh-keygen -t rsa -f /tmp/version.check -o -a 100 -q -N "" < /dev/null 2> /dev/null; echo $?` # Solaris 11.3's OpenSSH do not support ED25519 keys (Source: https://twitter.com/darrenmoffat/status/641568090581528576), but do support the option to use bcrypt to protect keys at rest. Since that option is common to all newer implementations of OpenSSH, that's what will be used for the version check from now on.

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
    printf "Your OpenSSH version is too old to run happy-dance. Upgrade to 6.5 or above.\n"
    exit 1
fi

rm -rf /tmp/version.check* # Just doing some house keeping.

generate_host_ssh_keys() {
        ssh_path="$1"
        cp etc/ssh/sshd_config "${ssh_path}/sshd_config"
        cd "${ssh_path}"
        rm ssh_host_*key*
        ssh-keygen -t ed25519 -f ssh_host_ed25519_key -q -N "" < /dev/null 2> /dev/null
        ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -q -N "" < /dev/null
        ED25519_fingerprint="$(ssh-keygen -l -f ${ssh_path}/ssh_host_ed25519_key.pub 2> /dev/null)"
        RSA_fingerprint="$(ssh-keygen -l -f ${ssh_path}/ssh_host_rsa_key.pub)"
        ED25519_fingerprint_MD5="$(ssh-keygen -l -E md5 -f ${ssh_path}/ssh_host_ed25519_key.pub 2> /dev/null)"
        RSA_fingerprint_MD5="$(ssh-keygen -l -E md5 -f ${ssh_path}/ssh_host_rsa_key.pub 2> /dev/null)"
}

generate_moduli() {
        moduli_path="$1"
        printf "Your OS doesn't have an $moduli_path file, so we have to generate one. This might take a while.\n"
        ssh-keygen -G "${HAPPYTMP}/moduli.all" -b 4096
        ssh-keygen -T "${moduli_path}" -f "${HAPPYTMP}/moduli.all"
}

modify_moduli() {
        moduli_path="$1"
        printf "Modifying your $moduli_path\n"
        awk '$5 > 2000' "$moduli_path" > "${HAPPYTMP}/moduli"
        mv "${HAPPYTMP}/moduli" "$moduli_path"
}

# The ssh_client function takes the time to check for the existence of keys
# because deleting or overwriting existing keys would be bad.

print_for_solaris_users() {
        printf "\nSolaris 11.2 and older users need to install OpenSSH from OpenCSW in order for happy-dance to work.\n"
        printf "Solaris 11.3 users can get OpenSSH by running the following commands:\n"
        printf "pkg uninstall ssh\n"
        printf "pkg install openssh\n"
        printf "You can verify the ssh version before and after by running 'pkg mediator ssh' and looking at the 'IMPLEMENTATION' column or by running 'ssh -V' and reading the output.\n\n"
}

ssh_client() {
        printf "This option replaces your ssh_config without backing up the original.\n"
        printf "Root or sudo access is requuired to do this. Are you sure you want to proceed? (y/n) "
        read yn
        case $yn in
                [Yy]*) printf "Replacing your ssh client configuration file...\n"
                        ;;
                *)
                        exit
                        ;;
        esac

        if [ -f /usr/local/etc/ssh/ssh_config ]; then
                cp etc/ssh/ssh_config /usr/local/etc/ssh/ssh_config
        else
                cp etc/ssh/ssh_config /etc/ssh/ssh_config # Removed $PWD
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
                        printf "You already have an RSA key but it's only $KEYSIZE bits long.\n"
                        printf "You should delete or move it and re-run this script, or generate another key by hand!\n"
                        printf "The command to generate your own RSA key pair is:\n\n"
                        printf "     ssh-keygen -t rsa -b 4096 -o -a 100\n"
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
                        printf "Refusing to duplicate effort in your .bash_profile\n"
                else
                        printf "unset SSH_AUTH_SOCK\n" >> ~/.bash_profile
                fi
                printf "Since you use Mac OS X, you had to have a small modification to your .bash_profile\n"
                printf "in order to connect to remote hosts. Read here and follow the links to learn more: http:/serverfault.com/a/486048\n\n"
                printf "OpenSSH will work the next time you log in. If you want to use OpenSSH imediately, run the following command in your terminal:\n"
                printf "unset SSH_SOCK_AUTH\n"
                printf "You only have to run that command once. That line is in your .bash_profile\n and will automatically make OpenSSH work for you on all future logins.\n"
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
        printf "This option destroys all host keys and replaces your sshd_config file.\n"
        printf "Are you sure want to proceed? (y/n) "
        read yn
        case $yn in
                [Yy]*) printf "Replacing your ssh server configuration file...\n"
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

        printf "Your new host key fingerprints are:\n"
        printf "$ED25519_fingerprint\n" 2> /dev/null
        printf "$RSA_fingerprint\n"
        if [ -n "$ED25519_fingerprint_MD5" ]; then
                printf "$ED25519_fingerprint_MD5\n" 2> /dev/null
        fi

        if [ -n "$RSA_fingerprint_MD5" ]; then
                printf "$RSA_fingerprint_MD5\n"
        fi
        printf "Don't forget to verify these!\n"

        if [ $UNAME = "SunOS" ]; then
                print_for_solaris_users
        else
                printf "Without closing this ssh session, do the following:
                1. Add your public key to ~/.ssh/authorized_keys if it isn't there already
                2. Restart your sshd.
                3. Remove the line from the ~/.ssh/known_hosts file on your computer which corresponds to this server.
                4. Try logging in. If it works, HAPPY DANCE!\n"
        fi
        exit
}

# This last bit of code just defines the flags.

while getopts "cs" opt; do
    case $opt in

        c)
            ssh_client
        ;;

        s)
            ssh_server
        ;;

        \?)
            printf "$opt is invalid.\n"
        ;;
    esac
done
