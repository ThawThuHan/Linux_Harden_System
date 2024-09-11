#!/bin/bash
options=''
case $1 in
-c | --check)
    options="check"
    ;;
-h | --help | "")
    echo '''
Usage: Command [Options]

    -a|--apply  apply best practice setting
    -c|--check  check your System is whether running with best practice
    -h|--help   help
    -v          print version
    '''
    ;;
-v)
    echo "version 1.0"
    ;;
-a | --apply)
    options="apply"
    ;;
esac

if [[ $EUID != 0 ]]; then
    echo "ERROR: You need to be root to run this script"
    exit 1
fi

os_release=$(cat /etc/os-release | grep ID_LIKE)

check_os() {
    if [[ "$os_release" == *"debian"* || "$os_release" == *"ubuntu"* ]]; then
        $1
    else
        $2
    fi
}

check_command() {
    if [[ $? == 1 ]]; then
        exit
    fi
}

green() {
    echo -e "\033[0;32m$1\033[0m"
}

red() {
    echo -e "\033[0;31m$1\033[0m"
}

bg_blue() {
    echo -e "\033[0;44m$1\033[0m"
}

# Function to check if a module is enabled in a PAM configuration file
if [[ $options ]]; then
    check_pam_policy() {
        local pam_file=$1
        echo "Checking PAM configuration in $pam_file"
        echo "-----------------------------------------------"
        sleep 2
        # Check if pam_pwquality.so is used for password complexity
        if grep -q "pam_pwquality.so" "$pam_file"; then
            green "Password complexity module (pam_pwquality) is configured."
            pam_pwquality=1
        else
            echo "Password complexity module (pam_pwquality) is NOT configured."
            pam_pwquality=0
        fi
        if grep -q "pam_pwhistory.so" "$pam_file"; then
            green "Password complexity module (pam_pwhistory) is configured."
            pam_pwhistory=1
        else
            echo "Password complexity module (pam_pwhistory) is NOT configured."
            pam_pwhistory=0
        fi
    }

    password_aging(){
        if grep -q "^$2" "$1"; then
            check_day() {
                VALUE=$(grep -E "$2.*([0-9]+)" $1)
                echo "Password expiration ($2) is set \"$(echo $VALUE | awk '{print $2}')\"."
            }
            if [[ $options == "apply" ]]; then
                echo ""
                check_day $1 $2
                read -p "Would you like to Change $2(y|n)? " answer
                if [[ $answer == "y" ]]; then
                    read -p "$2 : " value
                    sed -i "s|$VALUE|$2   $value|g" $1
                    check_command
                fi
            else 
                check_day $1 $2
            fi
        else
            echo "Password expiration ($2) is NOT set."
        fi
    }

    # Function to check login.defs file for password expiration policies
    check_login_defs() {
        local defs_file="/etc/login.defs"
        echo ""
        echo "Checking password aging policy in $defs_file"
        echo "--------------------------------------------------------"
        sleep 2
        
        password_aging "$defs_file" "PASS_MAX_DAYS"
        password_aging "$defs_file" "PASS_MIN_DAYS"
        password_aging "$defs_file" "PASS_WARN_AGE"
    }

    # Main script logic
    bg_blue "Password Policy Checking....!!!"
    # Check common-password or system-auth based on distro
    if [ -f /etc/pam.d/common-password ]; then
        check_pam_policy "/etc/pam.d/common-password"
        if [[ $options == "apply" && ($pam_pwhistory == 0 || $pam_pwquality == 0) ]]; then
            read -p "Would you like to apply password policy module (y|n)? " answer
            if [[ $pam_pwquality == 0 && $answer == 'y' ]]; then
                apt update
                apt install libpam-pwquality -y
                grep "pam_pwquality" /etc/pam.d/common-password || echo -e "password\trequisite\t\t\tpam_pwquality.so retry=3 enforce=1" >>/etc/pam.d/common-password
            elif [[ $pam_pwhistory == 0 && $answer == 'y' ]]; then
                grep "pam_pwhistory" /etc/pam.d/common-password || echo -e "password\trequisite\t\t\tpam_pwhistory.so remember=3" >>/etc/pam.d/common-password
                check_pam_policy "/etc/pam.d/common-password"
            fi
        fi
    elif [ -f /etc/pam.d/system-auth ]; then
        check_pam_policy "/etc/pam.d/system-auth"
        if [[ $options == "apply" && $pam_pwquality == 0 ]]; then
            read -p "Would you like to apply password policy module (y|n)? " answer
            if [[ $answer == 'y' ]]; then
                dnf update
                dnf install libpwquality
                grep "pam_pwquality" /etc/pam.d/system-auth || echo -e "password\trequisite\t\t\tpam_pwquality.so retry=3 enforce=1" >>/etc/pam.d/system-auth
            fi
        fi
    else
        echo "PAM password policy file not found."
    fi

    # Check /etc/login.defs for aging policies
    check_login_defs

    # Check for pwquality.conf (optional, depending on the system)
    if [ -f /etc/security/pwquality.conf ]; then
        echo ""
        echo "Checking password quality settings in /etc/security/pwquality.conf"
        echo "------------------------------------------------------------------"
        sleep 2
        grep -E "^minlen|^dcredit|^ucredit|^lcredit|^ocredit" /etc/security/pwquality.conf
    else
        echo "/etc/security/pwquality.conf file not found."
    fi
    echo ""
    echo "Password policy check completed."
    echo "==============================================="
    sleep 1
    echo ""
    bg_blue "SSH Security Best Practice Check...!!!"
    check_ssh_config() {
        local sshd_config=$1
        echo "Checking SSH Configuration in $1"
        echo "-------------------------------------------"
        sleep 2
        if grep -q "#PermitRootLogin Yes" $sshd_config || grep -q "#PermitRootLogin prohibit-password" $sshd_config; then
            red "PermitRootLogin is not set to \"No\""
        fi
        grep -q "PasswordAuthentication yes" $sshd_config && red "PasswordAuthentication is set to yes, should change to no."
        grep -q "PubkeyAuthentication yes" $sshd_config || red "PubkeyAuthentication is not set. Should use Public Key authentication instead of Password."
        grep -q "PermitEmptyPasswords yes" $sshd_config && red "PermitEmptyPasswords is set to yes, should change to no."
        grep -q "AllowUsers" $sshd_config || red "AllowUsers is not set, should allow only authorized users."
        grep -q "Port 22" $sshd_config && red "SSH Server Port is used standard Port Number, should change to non-standard Port Number."
        grep -q "ListenAddress 0.0.0.0" $sshd_config && red "SSH Server is listen on any ip address, should only listen on trusted network ip."
    }

    check_ssh_config /etc/ssh/sshd_config

    echo ""
    echo "SSH Security Best Practice check completed."
    echo "==============================================="
    echo ""
    bg_blue "Firewall Status Check...!!!"

    function check_ufw {
        if [[ -x /usr/sbin/ufw ]]; then
            if ufw status | grep -q "Status: active"; then
                echo "ufw is active."
            else
                red "ufw is inactive."
            fi
        else
            echo "ufw is not installed."
        fi
    }

    function check_firewalld {
        if [[ -x /usr/sbin/firewalld ]]; then
            if firewalld-cmd --status | grep -q "active"; then
                echo "firewalld is active."
            else
                echo "firewalld is inactive."
            fi
        else
            echo "firewalld is not installed."
        fi
    }

    check_firewall_on() {
        echo "Checking firewall status"
        echo "---------------------------"
        sleep 2
        check_os check_ufw check_firewalld
    }
    check_firewall_on
fi
