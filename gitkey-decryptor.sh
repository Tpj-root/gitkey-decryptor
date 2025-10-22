#!/bin/bash
###############################################################################
# Script Name   : gitkey-decryptor.sh
# Description   : A set of tools to manage GitHub keys, encryption/decryption,
#                 hex conversion, and folder organization.
# Author        : ROOT Tpj-root 
# Contact       : --
# Version       : 1.0.0
# Created       : 2025-10-22
# Last Modified : 2025-10-22
# License       : MIT
###############################################################################

# Usage:
# ./gitkey-decryptor.sh
# Ensure all required functions are defined in this script before running.

# ============================================================================ #
#                            MAIN WORKFLOW EXAMPLE                              #
# ============================================================================ #
# 1. create_project_dirs       # Create necessary project folders
# 2. hex_to_bin                # Convert encrypted hex string to binary
# 3. decrypt_file              # Decrypt the binary file using password
# 4. move_id_rsa               # Move the RSA key to secure folder
# ============================================================================ #




create_project_dirs() {
    # Set the base directory where folders will be created
    # $HOME is the current user's home directory
    # In this case, folders will be created in ~/Desktop
    base_dir="$HOME/Desktop"

    # Define an array of folder names to create
    # You can easily add/remove folder names here
    dirs=("MY_GIT" "RUN_TIME" "IM_FILES" "TEMP_FILES" "BUILD_FILES" "LIB_FILES")

    # Loop through each folder name in the array
    for d in "${dirs[@]}"; do
        # mkdir -p will:
        # 1. Create the folder if it doesn't exist
        # 2. Skip creation if the folder already exists (no error)
        # "$base_dir/$d" ensures the folder is created inside the base directory
        mkdir -p "$base_dir/$d"

        # Print a message showing the folder has been created or already exists
        echo "Created or exists: $base_dir/$d"
    done

    # Print a final message after all folders are processed
    echo "All folders ready in $base_dir"
}



hash_check() {
    if [ -z "$1" ]; then
        echo "Usage: hash_check <filename>"
        return 1
    fi
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi

    echo "MD5:    $(md5sum "$file" | awk '{print $1}')"
    echo "SHA1:   $(sha1sum "$file" | awk '{print $1}')"
    echo "SHA256: $(sha256sum "$file" | awk '{print $1}')"
    echo "SHA512: $(sha512sum "$file" | awk '{print $1}')"
}

hash_backup() {
    if [ -z "$1" ]; then
        echo "Usage: hash_backup <filename>"
        return 1
    fi
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi

    # Safe timestamp
    timestamp=$(date | tr -d ' :')
    backup_file="${file}_hash_backup_${timestamp}.txt"

    {
        echo "File: $file"
        echo "MD5:    $(md5sum "$file" | awk '{print $1}')"
        echo "SHA1:   $(sha1sum "$file" | awk '{print $1}')"
        echo "SHA256: $(sha256sum "$file" | awk '{print $1}')"
        echo "SHA512: $(sha512sum "$file" | awk '{print $1}')"
        echo "-----------------------------"
    } >> "$backup_file"

    echo "Hashes saved to $backup_file"
}

hash_verify() {
    if [ -z "$1" ]; then
        echo "Usage: hash_verify <filename>"
        return 1
    fi
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi

    # Find latest backup file for this filename
    backup_file=$(ls "${file}_hash_backup_"*.txt 2>/dev/null | sort | tail -n1)
    if [ -z "$backup_file" ]; then
        echo "No hash backup found for $file"
        return 1
    fi

    echo "Verifying '$file' against backup: $backup_file"
    echo "----------------------------------------"

    # Read stored hashes
    md5_stored=$(grep '^MD5:' "$backup_file" | awk '{print $2}')
    sha1_stored=$(grep '^SHA1:' "$backup_file" | awk '{print $2}')
    sha256_stored=$(grep '^SHA256:' "$backup_file" | awk '{print $2}')
    sha512_stored=$(grep '^SHA512:' "$backup_file" | awk '{print $2}')

    # Compute current hashes
    md5_now=$(md5sum "$file" | awk '{print $1}')
    sha1_now=$(sha1sum "$file" | awk '{print $1}')
    sha256_now=$(sha256sum "$file" | awk '{print $1}')
    sha512_now=$(sha512sum "$file" | awk '{print $1}')

    # Verification function
    verify() {
        if [ "$1" = "$2" ]; then
            echo -e "$3: OK ✅"
        else
            echo -e "$3: MISMATCH ❌"
        fi
    }

    verify "$md5_stored" "$md5_now" "MD5"
    verify "$sha1_stored" "$sha1_now" "SHA1"
    verify "$sha256_stored" "$sha256_now" "SHA256"
    verify "$sha512_stored" "$sha512_now" "SHA512"

    echo "----------------------------------------"
    echo "Verification complete."
}



encrypt_file() {
    if [ -z "$1" ]; then
        echo "Usage: encrypt_file <filename>"
        return 1
    fi
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi

    read -s -p "Enter encryption password: " key
    echo
    read -s -p "Confirm password: " key2
    echo
    if [ "$key" != "$key2" ]; then
        echo "Passwords do not match!"
        return 1
    fi

    output_file="enc_$file"
    openssl enc -aes-256-cbc -salt -in "$file" -out "$output_file" -pass pass:"$key"
    if [ $? -eq 0 ]; then
        echo "File encrypted successfully: $output_file"
    else
        echo "Encryption failed."
    fi
}


decrypt_file() {
    # Find encrypted files excluding .txt files
    enc_files=()
    for f in enc_*; do
        # Only include files, skip .txt
        [[ -f "$f" && "$f" != *.txt ]] && enc_files+=("$f")
    done

    # Check if any files found
    if [ ${#enc_files[@]} -eq 0 ]; then
        echo "No encrypted binary files (enc_*) found in current folder."
        exit 1   # use exit if running as standalone script
    fi

    # Loop through encrypted files
    for enc_file in "${enc_files[@]}"; do
        # Original filename
        orig_file="${enc_file#enc_}"

        # Ask for password
        read -s -p "Enter decryption password for $enc_file: " key
        echo

        # Decrypt
        openssl enc -d -aes-256-cbc -in "$enc_file" -out "$orig_file" -pass pass:"$key"
        if [ $? -eq 0 ]; then
            echo "Decrypted successfully: $orig_file"
        else
            echo "Failed to decrypt $enc_file. Wrong password?"
        fi
    done
}



file_to_hex() {
    if [ -z "$1" ]; then
        echo "Usage: file_to_hex <filename>"
        return 1
    fi
    file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi

    # Check if xxd is available
    if ! command -v xxd &>/dev/null; then
        echo "xxd not found. Installing..."
        sudo apt update && sudo apt install -y xxd
        if [ $? -ne 0 ]; then
            echo "Failed to install xxd. Exiting."
            return 1
        fi
    fi

    # Output file
    hex_file="${file}.hex"

    # Convert file to hex
    xxd -p "$file" | tr -d '\n' > "$hex_file"

    echo "Hex value saved to $hex_file"
}


hex_to_bin() {
    # Multi-line hex string
    hex_file="53616c7465645f5f8c6592ac743db9d3b98aa9361d6ac45ee62dd1588e31615aa17b3bdebbaaaad55b7264eea28c888c6b6a19f75c2d139639c9b9cc340fe5390a17ed535e9063537fd8e8142eaf0e73ee15c0d6c4d5f743efce5ffa1b954a2516b37a6d03d853c47f607257f1bb5b10a4359d1634c90f4a7d37c726903fb398362822155346fde227c27778a95f5c7be97c861441bdceae2fb71225f2e5452fcc7092f3ef24552ad55ff7edcafafdeb1f7e56cb8a4ad0193561e87f0dfdd19f19cd9dbe5bb188d70573f0d94431b7c0aecce9f2922f0c71b089ad57bfa7a1adef457ef6b751d010b4ca71ead4c6ef6973934cd3be2eed8fe909df2d8574f651df047a5d0e95c915f4549c9c6d5327bc62376651a2dbf2d7b4562e39882b7088629c87a777d67a81a71ed57b64d21486ef158cfeb0cb7dc8cc3d3bea0f36dfd0510acdb0891219e03798f69f10b0ef8287c2783febd4bf4a8be7caeb0f7129b1a7be69f81fd37828669a77c975f1ab09dfc33ceb02c0780bc8fef3dcf6aad841f3fc775ac51246b5ce398323ca7e647c7526cdb5e6a316f6ca38d7b0a9cff5f897377dad8e9a8b114c462fd2eb744062f30dc0692dccf89bb876017d32e5a099426c6dd39d6a354c70aff590f0cc5e45f458fdcd431a9238b711e2faf494e7fac7f014a3ae9e8ff6ff3f0953964cca3b7f5f5e761c8a7885f345dcfe6785f4dd250a6176462bc65ac19b38e78be7803d50ce473394af6c15e70376c572aa4ebae24628ad0e33a4235e1723171ab1b64f6335041c0d8b11e16733367e04f2d1593b4476f82f5360f76d174f126fc145f37f55e77a4309e8723fe11b3ec0b9804380c199483a68f79e129177e71dc397a6c281ca622332169dbf9992e49daee07b707213a211e03957f33a4290ee20dfc5deb8de8bb5bed637732cf7434c73d1686b35b5a2c47dcf6695f6fb9f3a1fda00a565252a033bd0f113ee434aa409641b050962ebf11e4d1d52c0c14463539f9b299f580633bd215bb4f419d62a32b5c9954c4c0ae34db4681946b7670f30235ef223a07d4f56dae1fbc2c6dc2cfa4a6b7a470e4e02700418fe2239487aee28b664b21578c9f0997f4fc41221219c3050860f6a58019957ceb9cdd32a4234cb76cfbdeae99df06941656370da8b678cb0e464b9c458159ead59e66e74f6b6ce78a36571c1329b6d6177fd8ab69fae703f1e64f537ce2d3ab193259cd029933a85eee4b2a36e76ef7606e0b7548acf12e7bd6099e3c6f3d36fa25d3864ad358629c08c449f268d1afd652097bf5378a253659b7d2c2d5f43017eb4b0c934ccf6e2e46df798a15e4c41ab7a4802eb7cd5b7c25891bb0c90cc3242556154d955c65870fb0d8518e2d3ea92ddf67cc87b4c92b0cc1678f6307ae306aca81f8e6461dbce775ccf57fe8ab92982a32694d7deb03d977ef40b911bbe17c1b3f3e52515d915f1cb1abc467df82c4fe1377b50989fab773145be8626a89a547aa4edd963301678eafd4fcc188031043e34db03430c64c7fcee97def1b69e5bacc8ab2a155a86f1f5ce8532b376dac139c8312146b5d12d9015426ff75b705f7ae26eb6612abe098b55b961cbf0e51d79514a970c774440264fb38f26c0e4a29e4fc7710d2d6daca0872c88c92a515e9582e5c928e169e30377c194170c831a0f3f2a6c981a4d686c5ce45c177bbd5cf5dc9ef0067717f161bd3e002ee9689ee897d5b06d2b631947d2f76e3a740835d14ebddc0451b4cb792f14eb66aa8d0352c333519bdacd7ab552a57c1f8c385f7df475fb1da201fd308e8b3b0a89345b6740988c52d54619e1f9bca26e7bcd9826f7a57926fcad6cb0f45b62ed6c301f605ce55df56efe65e2ee1999f79fd191b570dd27e014cd5f7281372d719538c4f9b783fb2576443f2af691b75c2696af313a01c4ae1202e43579ce160693ebb94d05693f7c08337ac1da1d4c5ce5f062bfcae78ace3376a34c617e8173d33882c310e1e9116e35656b03777a5fc9adff66dac415a72bf9a9d3ec196a5da04059740a9b7091c73c97d5767378ef7fbad6ae857f24ed662bf62ae1a9429f4c9759c6c985d6864a875431da0a63394ced4257880e2627d76dcb8cc2a867ce03b05a692469635cae34e495a18163023207a094b9dad064d2790fc918d0ff40638a7fabfa609e652386b61b8124884ff4e330815bcf3f06038926ca1b0daeed0c3a057906d102e2f0acc508c1014dbc554287691ed2e15e9a7e8b9c02ba4b69ab8b11b92a330873446716aebeaae601130209255c3f3469e72b52eb2162ef26f32cdaeb26a97339ca9bf88a891d4f8da940bc426c2cbbed0ae7b3d236721bd8940389cdf7ea07940c212581bc3bf767f16285dcdcb1e569fef48f1c68ac5956c2b0a630f52253be1f9f13197c2563d3e5ad1366216f300e5f3412d9964a9753a864c83144af0815045a12a872d93e7fcad2aa713b2cc638b02acd23f2ceaa0d74cd8d84ae73c48ecbd1264c99899c7c5cd40e21d0ab72f07be5e8f470cde631c1ac9dbc594c6c83f62a3b81914675da15cf0f2a99aa366f456c366ecaa46ee5ba315d46ea4424f1f3a7436f165f55a625caa25c7f6c8150b3bc578e4b63fe855116a6f5be8528e8686f1ef51dda34944ab3f30f35a4f1bd3af0fe15b8b0d2fca9ddf60ccb002fb36cf8a6992aa4494e3e44b2aa1d97aee9f1f450f85b1f70cc2f1faaaf2c09762fd3adcdfcdb3a13f529ddf0d0ddf7aa5809c037a5e91dd920fd9976f78fb711f0c7730c5a604079e0b2e2ba2d504b9aa9673ab10bcee0178d6c47e390a0f3718da0d851a942812f99ac32ecfe114dca6614cbda6a2ba1795ab853dd34e200f3f2bea123cf15f83b63933c54e93d7f5988a3eed8c24a31e9a6e6c4c41ef93ceb2e9bb010a9c6250398963bb9f547a62a2636cf475e71190f5fac62d1160debf9135485f10064d33816058cc1ae2943afb071f1dd590165b93db293aaab5a6170af298abc443ab56cb81a7dbd5b197db55176540ffe57c831764bfe01546484ef22bd61201d461e8254fb54411e8208bd9638c9b2dbf8b02a97bf547c5a9afe5236731b925c04cfa9b63b9411ca546d93ae57d9246846f2212eaa5e65883a90891ab182656c5cff9a3ab4b29cd4bf540019e28f24961515badec8e5353f1bb6a9a37282f2153d9f3a215a0124b79d1df2c629148abbbeb1d104d17e92d6e6e9bb0cd2a87d2e01c8d20f9c7c22d7049954d482ed65cf0a82bb21cc18cc0f214bd27b37289a46a5574d3c9cd27fee87120e0307f13c9ec9dda38b6f1ad7272971f127ded937a69aa08581550402175ee02f8406599f61d2ef2ca92756ab4d37dc5b76ae842c868513b18e407bfdda2672adefa43b324763e96c14a5c2eddc65d51e643d1e68f3b3f545ba4b561e828daadcade294843144bec4732e5f6b3d432ea457c068646a6d9557cb4d444aae24d3c1d644d86ae8aad8831800469a469225dff03e31aedbcfc8dd578d843040325bca2ae24632a21f68f9f2c373def4fd642988ea1c38055e84f1bc6b63aaef2bd773d18b01c5350041f0515af0d516f83392f4d73116abe3a0a2d9eebea611e9f62270939ebdb9411d65dc60d931b7725309e01e1b8955329f241702a9dcfb8ca908d2633b7d884c06e204365875cd5e3c18ba6938c37adf9d79906e3ed213108caa3e74998bac922088c02273bcf70e7cbcac3192e8a0e002f3cbd2222aa9375eeea8b87d315eb7bde3a26d036a191dd5f23363e3dc6f766b25ab1edcce6624b93eab37e50031f84d98532a68f5083b59c159238a5229cce615876f70a6918e1b3f6819f08600455761fd57b7b54bfa8b5cace9774c401ea4f7378585671d4e10c080788718de9ffe215964530b0d26327033785661cf73c7b157dd14bd86373d654ec2b592e21ca51dcfb9938d4ae671b2b458b62c4e1399b329063050adceb14cf8d913dbd55581039b13bd8a4a3ff5eacf8f5174b9d3508903e463ff8e43b555837d251e641c9a8ad41f91fb7f0ad1787fb9ea1d462f60b1f5e8dd68a8231c050cb863d83688da28ff3d8cf0cf3a45fc2b1e2a238aa8686387da215a544421fbd85ece61ca3f435834a014239489503396b30b2642cb85927695806f3634297d4bda306e275fdefea4538d78ae0e455c458b59f33fbc42c568d05c5db8d087e0f0f9faa230307bf45560d093c24d9b0022062968dd7bbba47c782d6028a690f1125a40cab0b7a8a6a3556c2d44bed5f3871ca52a7828ccd396ddb485bd415222df28d7e9e51d075e60228e83c1115a64090ac38eeee7248ec1d9ff273c01cef9ec3074f840f55701c7def8a493f49000d2ed8b84f273cb975452f8a94c926f12ada44126ce3ea603a0494563320a0c7e6f42758ea794fe0c4b2fa5bb68d9e9256e404fe06e2fdaeff4bc7c231bfa7a2852e47bd207982159063092a3a002c3dc3cbdbad9af250e87ac995158bcdc2b259f2bb7a4fdbb03f67228f7f0064eed4fe9ab50a81f28382cf46c3ebb0dc47849f0cb455176d07492f183e63854589b756ccee190fc3b87e72d664570a33159d78f2b48cd8e7959ff2ebf6f2af07f62ab75019eb462cda5d7ddf5d2c250ed24000c8d9a56cd1efabd36a7199cf3e6b7108af2539bac3096e2058c8d9d0016e602c3694a68d350d73d927dd45f2248672fcd369431feddb77e0226ccc8779841f315f6ef93633eef955d540a006ec4e092e9ba1210dc1cf0d39180caf6dd2cd48ab3d48ba53ce5984f0a9b9d61bd56c50baf17367b10de8d484f17a4d1d9f2267eded391c9e1eb6fedfd34e8f168d20afa10077d91091817d7b4b3a50330375aabaa24a0dbad8befa421bf6d398e454204fead237bd54a1dc11e659b46b9e376aba90e"

    # Output binary filename
    output_file="enc_id_rsa"

    # Convert hex string to binary (remove newlines first)
    echo "$hex_file" | tr -d '\n' | xxd -r -p > "$output_file"

    echo "Binary file created: $output_file"
}


move_id_rsa() {
    # Source file to move
    file="id_rsa"

    # Check if the file exists in current directory
    if [ ! -f "$file" ]; then
        echo "File '$file' not found in current directory."
        return 1
    fi

    # Destination folder
    dest="$HOME/Desktop/IM_FILES"

    # Create the destination folder if it doesn't exist
    mkdir -p "$dest"

    # Move the file
    mv "$file" "$dest/"

    echo "Moved '$file' to '$dest/' successfully."
}


secure_rsa_key() {
    # Fixed path to your RSA key
    key_file="$HOME/Desktop/IM_FILES/id_rsa"

    # Check if the key exists
    if [ -f "$key_file" ]; then
        # Set permissions to 600 (owner read/write only)
        chmod 600 "$key_file"
        echo "Permissions set to 600 for: $key_file"
    else
        echo "RSA key not found at $key_file"
    fi
}


git_setup_remote() {
    # Input: GitHub repo URL (SSH)
    local repo_url="$1"

    if [ -z "$repo_url" ]; then
        echo "Usage: git_setup_remote <git@github.com:user/repo.git>"
        return 1
    fi

    # Check if we are inside a Git repo
    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        echo "Not a Git repository. Initialize first with 'git init'."
        return 1
    fi

    # Check if remote 'origin' exists
    if git remote get-url origin &>/dev/null; then
        echo "Remote 'origin' exists. Updating URL..."
        git remote set-url origin "$repo_url"
    else
        echo "Adding remote 'origin'..."
        git remote add origin "$repo_url"
    fi

    echo "Remote URL set to: $repo_url"

    # Test SSH connection
    echo "Testing SSH connection..."
    ssh -T git@github.com
    if [ $? -eq 1 ] || [ $? -eq 255 ]; then
        echo "SSH connection successful (expected 'shell access denied' message)."
    else
        echo "SSH test may have failed. Check your keys and repo access."
    fi
}



# Early in your workflow
check_rsa_and_verify() {
    # Fixed path to RSA key
    key_file="$HOME/Desktop/IM_FILES/id_rsa"

    # Expected hash values
    expected_md5="2b39c611fcf8e136fe21a6ac3d1d03d9"
    expected_sha1="6d8ff8dbb73807451e30c8e7302ea926ed0438c0"
    expected_sha256="67f9996052644c5962b112ee17e10eac505976b22cdc71345cd225f1fab3100c"
    expected_sha512="e97a54a051b9e6a4926159d2c62d92b7582b1f436a04213119af51568efde7e0fc2bb97d837ead9e3683ad4307c5e291e76a196b649881da9c5938e1aebdcc1a"

    # Check if the file exists
    if [ ! -f "$key_file" ]; then
        echo "RSA key not found at $key_file"
        return 1
    fi

    echo "RSA key found at $key_file. Verifying hashes..."

    # Calculate actual hashes
    md5_actual=$(md5sum "$key_file" | awk '{print $1}')
    sha1_actual=$(sha1sum "$key_file" | awk '{print $1}')
    sha256_actual=$(sha256sum "$key_file" | awk '{print $1}')
    sha512_actual=$(sha512sum "$key_file" | awk '{print $1}')

    # Compare each hash
    if [[ "$md5_actual" == "$expected_md5" ]] && \
       [[ "$sha1_actual" == "$expected_sha1" ]] && \
       [[ "$sha256_actual" == "$expected_sha256" ]] && \
       [[ "$sha512_actual" == "$expected_sha512" ]]; then
        echo "All hashes match ✅. RSA key verified successfully."
        exit 0
    else
        echo "Hash mismatch ❌. RSA key may be corrupted or altered."
        return 1
    fi
}



check_rsa_and_verify








# MAIN
# Step-by-step workflow for managing, verifying, and securing your files

# 1st: Create all necessary project folders on Desktop
echo "Step 1: Creating project folders..."
if create_project_dirs; then
    echo "Project folders ready."
else
    echo "Failed to create project folders. Exiting."
    exit 1
fi

# 2nd: Convert your encrypted hex string into a binary file
echo "Step 2: Converting hex to binary..."
if hex_to_bin; then
    echo "Binary file created successfully."
else
    echo "Failed to convert hex to binary. Exiting."
    exit 1
fi

# 3rd: Verify the hash of the encrypted binary file before decryption
echo "Step 3: Verifying encrypted binary hash..."
if hash_verify enc_id_rsa; then
    echo "Encrypted file hash verified."
else
    echo "Encrypted file hash mismatch. Exiting."
    exit 1
fi

# 4th: Decrypt the binary file using the password you input
echo "Step 4: Decrypting binary file..."
if decrypt_file; then
    echo "Decryption successful."
else
    echo "Decryption failed. Exiting."
    exit 1
fi

# 5th: Verify the hash of the decrypted RSA key to ensure integrity
echo "Step 5: Verifying decrypted RSA key hash..."
if hash_verify id_rsa; then
    echo "Decrypted RSA key hash verified."
else
    echo "Decrypted RSA key hash mismatch. Exiting."
    exit 1
fi

# 6th: Move the decrypted RSA key to the proper folder for safe storage
echo "Step 6: Moving RSA key to secure folder..."
if move_id_rsa; then
    echo "RSA key moved successfully."
else
    echo "Failed to move RSA key. Exiting."
    exit 1
fi

echo "All steps completed successfully!"


# 7th: Clean up temporary encrypted binary file
echo "Step 7: Cleaning up temporary files..."
if [ -f "enc_id_rsa" ]; then
    rm -f "enc_id_rsa"
    echo "Temporary file 'enc_id_rsa' removed."
else
    echo "No temporary file 'enc_id_rsa' found. Nothing to clean."
fi


# 8th: Set secure permissions for the RSA key
echo "Step 8: Set secure permissions for the RSA key"

# Set secure permissions for the RSA key
secure_rsa_key
echo "RSA key permissions secured (600)."

echo "Step 8 completed."


# 9th:add or update the Git remote URL and then test the SSH connection automatically
git_setup_remote git@github.com:Tpj-root/gitkey-decryptor.git



#set private key and connect github profiles
#
#eval "$(ssh-agent -s)"
#ssh-add ~/.ssh/id_rsa
#git config --global user.name "Tpj-root"
#git config --global user.email "trichy_hackerspace@outlook.com"
#alias addkey='ssh-add $HOME/Documents/KEY/id_rsa'
#
#Check SSH Key Permissions:
#Ensure that your SSH key has the correct permissions.
#chmod 600 $HOME/Desktop/IM_FILES/id_rsa
#
### git alias
function gitremote() {
    local repo="$1"
    git remote set-url origin "git@github.com:Tpj-root/${repo}"
    echo "Switched remote to git@github.com:Tpj-root/${repo}"
}
##########################################
# 1 -- > git clone "URL"
# 2 -- > cd <repo_name>
# 3 -- > git remote set-url origin "git@github.com:Tpj-root/${repo_name}"
# 4 -- > xdg-open .
# 5 -- > gedit README.md
#
function mygit() {
    if [ -z "$1" ]; then
        echo "Usage: mygit <repository_url>"
        echo "Example: mygit https://github.com/Tpj-root/PCB_Prototype_Board.git"
        return 1
    fi

    cd $HOME/Desktop/MY_GIT
    local repo_url="$1"
    local repo_name=$(basename "$repo_url" .git)

    # Clone the repository
    git clone "$repo_url" || { echo "Failed to clone $repo_url"; return 1; }

    # Navigate into the repository directory
    cd "$repo_name" || { echo "Failed to cd into $repo_name"; return 1; }

    # Set the remote to SSH
    git remote set-url origin "git@github.com:Tpj-root/${repo_name}"
    echo "Switched remote to git@github.com:Tpj-root/${repo_name}"

    #open the current dir
    #xdg-open .

    #open the Readme file
    #gedit README.md
}


mygit https://github.com/Tpj-root/First_Step_Debian.git

mygit https://github.com/Tpj-root/gitkey-decryptor.git



add_alias_source() {
    local line='source $HOME/Desktop/MY_GIT/First_Step_Debian/alias_run.sh'
    local rcfile="$HOME/.bashrc"

    # check if already exists
    grep -Fxq "$line" "$rcfile" || echo "$line" >> "$rcfile"
    echo "Added source line to $rcfile (if not already present)."
}


add_alias_source


#---------------------------------------------------
# Function: install_jocker_from_gitkey
# Description: Uses your existing mygit function to clone
#              gitkey-decryptor repo, then installs jocker.sh
#              into /usr/local/bin with execute permission.
#---------------------------------------------------

install_jocker_from_gitkey() {
    local repo_url="https://github.com/Tpj-root/gitkey-decryptor.git"
    local base_dir="$HOME/Desktop/MY_GIT"
    local target_dir="$base_dir/gitkey-decryptor"
    local bin_path="/usr/local/bin/jocker.sh"

    echo ">>> Installing jocker.sh from gitkey-decryptor repo..."

    # Step 1: Clone using your existing mygit function
    mygit "$repo_url"

    # Step 2: Verify jocker.sh exists
    if [ ! -f "$target_dir/jocker.sh" ]; then
        echo "[ERROR] jocker.sh not found in $target_dir"
        return 1
    fi

    # Step 3: Copy to /usr/local/bin and set permission
    echo "[COPY] Moving jocker.sh to /usr/local/bin"
    sudo cp "$target_dir/jocker.sh" "$bin_path" && sudo chmod +x "$bin_path"

    echo ">>> jocker.sh installed successfully at $bin_path"
}



install_jocker




