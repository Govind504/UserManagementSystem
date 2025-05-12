#!/bin/bash

# Directories and files
BASE_DIR="/etc/ums"
USERS_DIR="$BASE_DIR/users"
CREDENTIALS_FILE="$BASE_DIR/credentials.txt"
BLOCKEDusers_FILE="$BASE_DIR/BLOCKEDusers.txt"
INTRUSION_LOG="$BASE_DIR/intrusion_log.txt"
LOGIN_ATTEMPTS="$BASE_DIR/login_attempts.txt"

mkdir -p "$USERS_DIR"
touch "$CREDENTIALS_FILE" "$BLOCKEDusers_FILE" "$INTRUSION_LOG" "$LOGIN_ATTEMPTS"

# Function: Log Intrusion Attempt
log_intrusion() {
    echo "$(date +"%F %T") | Intrusion attempt on username: $1" >> "$INTRUSION_LOG"
}

# Function: Check if user is blocked
is_blocked() {
    grep -q "^$1$" "$BLOCKEDusers_FILE"
}

# Function: Block User
block_user() {
    echo "$1" >> "$BLOCKEDusers_FILE"
}

# Function: Validate Login
login() {
    username=$(dialog --stdout --inputbox "Enter Username:" 10 40)
    if is_blocked "$username"; then
        dialog --msgbox "Your account is blocked. Contact Admin." 10 40
        return 1
    fi

    password=$(dialog --stdout --insecure --passwordbox "Enter Password:" 10 40)

    stored_hash=$(grep "^$username:" "$CREDENTIALS_FILE" | cut -d: -f2)
    if [[ -z "$stored_hash" ]]; then
        dialog --msgbox "User does not exist!" 10 40
        return 1
    fi

    input_hash=$(echo "$password" | sha256sum | cut -d' ' -f1)

    if [[ "$input_hash" == "$stored_hash" ]]; then
        sed -i "/^$username:/d" "$LOGIN_ATTEMPTS"
        if [[ "$username" == "admin" ]]; then
            admin_menu "$username"
        else
            user_menu "$username"
        fi
    else
        if [[ "$username" != "admin" ]]; then  # Only track failed attempts for non-admin users
            attempts=$(grep "^$username:" "$LOGIN_ATTEMPTS" | cut -d: -f2)
            attempts=$((attempts + 1))
            sed -i "/^$username:/d" "$LOGIN_ATTEMPTS"
            echo "$username:$attempts" >> "$LOGIN_ATTEMPTS"
            dialog --msgbox "Incorrect password! Attempt $attempts of 3" 10 40

            if [[ "$attempts" -ge 3 ]]; then
                if [[ "$username" != "admin" ]]; then
                    block_user "$username"
                    log_intrusion "$username"
                    dialog --msgbox "Too many failed attempts. User blocked!" 10 40
                fi
            fi
        else
            dialog --msgbox "Incorrect password for admin. Admin attempts are not tracked." 10 40
        fi
    fi
}

# Function: Signup
signup() {
    username=$(dialog --stdout --inputbox "Choose Username:" 10 40)
    if grep -q "^$username:" "$CREDENTIALS_FILE"; then
        dialog --msgbox "Username already exists!" 10 40
        return
    fi

    password=$(dialog --stdout --insecure --passwordbox "Choose Password:" 10 40)
    hash=$(echo "$password" | sha256sum | cut -d' ' -f1)
    echo "$username:$hash" >> "$CREDENTIALS_FILE"

    dialog --msgbox "Signup successful. Please login." 10 40
}

# Admin Menu
admin_menu() {
    while true; do
        choice=$(dialog --stdout --menu "Admin Dashboard" 15 50 8 \
            1 "Add User" \
            2 "Delete User" \
            3 "Assign Group" \
            4 "List Users" \
            5 "View Blocked Users" \
            6 "Unblock User" \
            7 "View Intrusion Logs" \
            8 "Logout")

        case $choice in
            1) add_user ;;
            2) delete_user ;;
            3) assign_group ;;
            4) list_users ;;
            5) view_blocked_users ;;
            6) unblock_user ;;
            7) view_intrusions ;;
            8) return ;;
        esac
    done
}

# User Menu
user_menu() {
    while true; do
        choice=$(dialog --stdout --menu "User Dashboard" 10 40 2 \
            1 "Change Password" \
            2 "Logout")

        case $choice in
            1) change_password "$1" ;;
            2) return ;;
        esac
    done
}

# Add System User
add_user() {
    newuser=$(dialog --stdout --inputbox "Enter new system username:" 10 40)
    if id "$newuser" &>/dev/null; then
        dialog --msgbox "User already exists." 10 40
        return
    fi
    password=$(dialog --stdout --insecure --passwordbox "Enter password:" 10 40)
    useradd -m "$newuser"
    echo "$newuser:$password" | chpasswd
    dialog --msgbox "System user '$newuser' added." 10 40
}

# Delete System User
delete_user() {
    user=$(dialog --stdout --inputbox "Enter username to delete:" 10 40)
    if ! id "$user" &>/dev/null; then
        dialog --msgbox "User does not exist." 10 40
        return
    fi
    dialog --yesno "Are you sure to delete $user?" 10 40
    [[ $? -eq 0 ]] && userdel -r "$user" && dialog --msgbox "User deleted." 10 40
}

# Assign Group
assign_group() {
    user=$(dialog --stdout --inputbox "Enter username:" 10 40)
    group=$(dialog --stdout --inputbox "Enter group:" 10 40)
    if ! getent group "$group" > /dev/null; then
        dialog --yesno "Group does not exist. Create?" 10 40
        [[ $? -eq 0 ]] && groupadd "$group"
    fi
    usermod -aG "$group" "$user"
    dialog --msgbox "User added to group." 10 40
}

# List Users
list_users() {
    awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd > /tmp/users.txt
    dialog --textbox /tmp/users.txt 20 50
    rm /tmp/users.txt
}

# View Blocked Users
view_blocked_users() {
    dialog --textbox "$BLOCKEDusers_FILE" 20 50
}

# Unblock User
unblock_user() {
    user=$(dialog --stdout --inputbox "Enter username to unblock:" 10 40)
    if grep -q "^$user$" "$BLOCKEDusers_FILE"; then
        sed -i "/^$user$/d" "$BLOCKEDusers_FILE"
        sed -i "/^$user:/d" "$LOGIN_ATTEMPTS"
        dialog --msgbox "User unblocked." 10 40
    else
        dialog --msgbox "User is not blocked." 10 40
    fi
}

# View Intrusions
view_intrusions() {
    dialog --textbox "$INTRUSION_LOG" 20 70
}

# Change Password
change_password() {
    newpass=$(dialog --stdout --insecure --passwordbox "Enter new password:" 10 40)
    newhash=$(echo "$newpass" | sha256sum | cut -d' ' -f1)
    sed -i "/^$1:/d" "$CREDENTIALS_FILE"
    echo "$1:$newhash" >> "$CREDENTIALS_FILE"
    dialog --msgbox "Password updated successfully." 10 40
}

# Main Menu
while true; do
    option=$(dialog --stdout --title "User Management System" --menu "Choose Option:" 15 40 3 \
        1 "Login" \
        2 "Signup" \
        3 "Exit")

    case $option in
        1) login ;;
        2) signup ;;
        3) clear; exit ;;
    esac
done
