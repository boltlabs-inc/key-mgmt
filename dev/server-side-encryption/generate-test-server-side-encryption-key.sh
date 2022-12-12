# This script should be run with `cargo make sse` from the root of this repo
# It generates a ChaCha20Poly1305 encryption key to be used on the server side
# The key is used for encrypting Signing Keys in the database

SCRIPT_DIR="dev/server-side-encryption"
KEY_DIR=$SCRIPT_DIR/gen
rm -rf $KEY_DIR

mkdir -p $KEY_DIR
chmod 700 $KEY_DIR

#Create server side encryption key, i.e. 32 random bytes that can be used as a ChaCha20Poly1305 key
openssl rand -out $KEY_DIR/remote_storage.key 32
