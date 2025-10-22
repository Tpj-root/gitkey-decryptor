#!/bin/bash
###############################################################################
# Script Name   : 
# Description   : Personal environment cleaner script.
#                 Removes temporary files, cache, logs, and other junk data
#                 to keep your Debian system and Git projects clean.
# Author        : Shadow (ROOT Tpj-root)
# Contact       : --
# Version       : 1.2.0
# Created       : 2025-10-22
# Last Modified : 2025-10-22
# License       : MIT
###############################################################################


# Usage:
# ./clean.sh


# ============================================================================ #
#                            MAIN WORKFLOW EXAMPLE                              #
# ============================================================================ #
# 1. create_project_dirs       # Create necessary project folders
# 2. hex_to_bin                # Convert encrypted hex string to binary
# 3. decrypt_file              # Decrypt the binary file using password
# 4. move_id_rsa               # Move the RSA key to secure folder
# ============================================================================ #



# Define color codes
#
#  color list
#
# Define colors function
function get_colors() {
    RESET='\033[0m'
    BLACK='\033[30m'
    RED='\033[31m'
    GREEN='\033[32m'
    #The 1; makes it bold/bright, which should look more vivid.
    YELLOW='\033[1;33m'
    # Some terminals render it as a darker yellow, which might appear brownish.
    #YELLOW='\033[33m'
    BLUE='\033[34m'
    MAGENTA='\033[35m'
    CYAN='\033[36m'
    WHITE='\033[37m'
    BOLD='\033[1m'
    UNDERLINE='\033[4m'
    GRAY='\033[90m'
    BRIGHT_RED='\033[91m'
    BRIGHT_GREEN='\033[92m'
    BRIGHT_YELLOW='\033[93m'
    BRIGHT_BLUE='\033[94m'
    BRIGHT_MAGENTA='\033[95m'
    BRIGHT_CYAN='\033[96m'
    BRIGHT_WHITE='\033[97m'
    BLINK='\033[5m'
}

# Call the function to define colors
get_colors




#---------------------------------------------------
# Function: warning_message
# Description: Displays a warning message in a table-style 
#              format, dynamically adjusting the width.
# Parameters:
#   $1 - Custom warning message (centered)
# Usage Example:
#   warning_message "This action cannot be undone!"
#---------------------------------------------------
warning_message() {
    local msg="$1"
    local msg_length=${#msg}
    local box_width=$((msg_length + 4))  # Add 2 spaces on each side

#    # Print top border
#    echo -e "🔴${RED}$(printf '=%.0s' $(seq $box_width))🔴"
#
#    # Print centered message
#    printf "| %s |\n" "$msg"
#
#    # Print bottom border
#    echo -e "$(printf '=%.0s' $(seq $box_width))${RESET}"


    echo -e "${RED}"
    printf "🔴 : %s \n" "$msg"
    echo -e "${RESET}"
}







#---------------------------------------------------
# Function: colored_yes_no
# Description: Returns a formatted string displaying 
#              "yes" in green and "no" in red, 
#              wrapped in parentheses.
# Usage Example:
#   echo -e "Do you want to continue? $(colored_yes_no): "
#---------------------------------------------------
function colored_yes_no() {
    echo -e "(${GREEN}yes${RESET}/${RED}no${RESET})"
}


#
#
#Turn on 2-Step Verification
#
#---------------------------------------------------
# Function: twoStepVerification
# Description: Asks the user twice for confirmation before executing.
#              If confirmed, it runs a test sequence (seq 1 10).
#              If the user aborts, it exits without executing.
#---------------------------------------------------

function twoStepVerification() {
    # Create Fucntion
    # echo -e "${RED}====================================================="
    # echo "  WARNING: This function will modify and delete files."
    # echo -e "=====================================================${RESET}"
    
    warning_message " WARNING: This function will modify and delete files."

    # First confirmation prompt
    echo -e "Do you really want to continue?  $(colored_yes_no): "
    read -r choice1
    if [[ ! "$choice1" =~ ^(yes|y|YES|Y)$ ]]; then
        echo "Aborted."
        return 1  # Return 1 to indicate failure
    fi

    # Second confirmation prompt for extra security
    read -p "Are you absolutely sure?  $(colored_yes_no): " choice2
    if [[ "$choice2" != "yes" ]]; then
        echo "Aborted."
        return 1  # Return 1 to indicate failure
    fi

    # If both confirmations are passed, proceed with execution
    echo "Executing the operation..."
    #seq 1 10  # Example operation
    echo "Operation completed successfully."
    return 0  # Return 0 to indicate success
}





#---------------------------------------------------
# Function: clean_project_dirs
# Description: Deletes all project directories created by create_project_dirs()
#              after double verification using twoStepVerification().
#---------------------------------------------------

clean_project_dirs() {
    base_dir="$HOME/Desktop"
    dirs=("MY_GIT" "RUN_TIME" "IM_FILES" "TEMP_FILES" "BUILD_FILES" "LIB_FILES")
    #dirs=("temp")
    echo ">>> Preparing to delete all project folders from: $base_dir"

    # Step 1: Run verification
    twoStepVerification || return 1

    # Step 2: If verification passed, start deletion
    for d in "${dirs[@]}"; do
        target="$base_dir/$d"
        if [ -d "$target" ]; then
            rm -rf "$target"
            echo "[DELETED] $target"
        else
            echo "[SKIP] $target (not found)"
        fi
    done

    echo ">>> All selected folders cleaned successfully."
}

clean_project_dirs

#---------------------------------------------------
# Function: remove_alias_source
# Description: Removes the alias source line from ~/.bashrc safely.
#              Uses two-step verification before modifying the file.
#---------------------------------------------------

remove_alias_source() {
    local line='source $HOME/Desktop/MY_GIT/First_Step_Debian/alias_run.sh'
    local rcfile="$HOME/.bashrc"

    echo ">>> Preparing to remove alias source line from: $rcfile"

    # Ask double confirmation
    twoStepVerification || return 1

    # Remove the line safely (only exact match)
    if grep -Fxq "$line" "$rcfile"; then
        sed -i "\|$line|d" "$rcfile"
        echo "[REMOVED] Alias source line from $rcfile"
    else
        echo "[SKIP] Line not found in $rcfile"
    fi

    echo ">>> .bashrc cleanup complete."
}

remove_alias_source


#---------------------------------------------------
# Function: remove_jocker
# Description: Safely deletes /usr/local/bin/jocker.sh
#              Uses two-step verification before removal.
#---------------------------------------------------

remove_jocker() {
    local bin_path="/usr/local/bin/jocker.sh"

    echo ">>> Preparing to remove jocker.sh from: $bin_path"

    # Ask double confirmation
    twoStepVerification || return 1

    if [ -f "$bin_path" ]; then
        sudo rm -f "$bin_path"
        echo "[REMOVED] $bin_path"
    else
        echo "[SKIP] File not found: $bin_path"
    fi

    echo ">>> jocker.sh cleanup complete."
}



