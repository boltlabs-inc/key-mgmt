SCRIPT_DIR="dev/server-side-encryption"
KEY_DIR=$SCRIPT_DIR/gen
rm -rf $KEY_DIR

mkdir -p $KEY_DIR
chmod 700 $KEY_DIR

#Create server side encryption key
openssl rand 32 -out $KEY_DIR/server_side_encryption.key
