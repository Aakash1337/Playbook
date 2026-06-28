#!/bin/bash

# Path to the file containing authorized users
AUTHORIZED_USERS_FILE="./users_file.txt"

# Function to remove unauthorized users
remove_unauthorized_users() {
    echo "Removing unauthorized users..."

    # Ensure the authorized users file exists
    if [ ! -f "$AUTHORIZED_USERS_FILE" ]; then
        echo "Authorized users file not found at $AUTHORIZED_USERS_FILE. Exiting..."
        exit 1
    fi

    # Ensure the authorized users file is not empty
    if [ ! -s "$AUTHORIZED_USERS_FILE" ]; then
        echo "Authorized users file is empty. Exiting..."
        exit 1
    fi

    # Read authorized users into an array
    AUTHORIZED_USERS=()
    while IFS= read -r user; do
        AUTHORIZED_USERS+=("$user")
    done < "$AUTHORIZED_USERS_FILE"

    # Get all system users from /etc/passwd
    SYSTEM_USERS=$(cut -d: -f1 /etc/passwd)

    # Loop through system users and remove unauthorized ones, excluding system integral users (UID < 1000)
    for user in $SYSTEM_USERS; do
        # Get the UID of the user
        USER_UID=$(id -u "$user" 2>/dev/null)

        # Skip system integral users (UID < 1000)
        if [ "$USER_UID" -lt 1000 ]; then
            echo "Skipping system integral user '$user' (UID: $USER_UID)."
            continue
        fi

        # Check if the user is in the authorized list
        if [[ ! " ${AUTHORIZED_USERS[*]} " =~ " $user " ]]; then
            echo "User '$user' is not authorized. Removing..."
            sudo deluser --remove-home "$user" || echo "Failed to remove user '$user'."
        else
            echo "User '$user' is authorized."
        fi
    done
}

# Call the function to remove unauthorized users
remove_unauthorized_users

echo "Unauthorized user removal complete."