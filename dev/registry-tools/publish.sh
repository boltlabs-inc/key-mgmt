# Exit script if any command returns an error
set -e

# Check for crate name arg
if [ $# -lt 1 ]; then
    echo "Syntax: publish.sh [crate-name]"
    exit 2
fi
CRATE_NAME=$1

# Read the version number from Cargo.toml.
if test -f Cargo.toml; then
    CRATE_VERSION=$(sed -rn 's/^version = "(.+)"/\1/p' Cargo.toml)
else
    echo "Cargo.toml not found. Try running this script from the root of the repo."
    exit 1
fi
echo Publishing $CRATE_NAME version $CRATE_VERSION

# Ensure that the registry's main branch is checked out
cd key-mgmt-registry
git switch main
cd ..

# Build crate and copy to local registry
cd $CRATE_NAME
cargo index add \
    --index ../key-mgmt-registry \
    --index-url https://github.com/boltlabs-inc/key-mgmt-registry \
    --upload ../key-mgmt-registry/files/$CRATE_NAME \
    -- \
    --allow-dirty

# Registry manifest is automatically committed.
# .crate file needs to be committed manually.
cd ../key-mgmt-registry
git add .
git commit -m "$CRATE_NAME-$CRATE_VERSION"
# Push local registry to remote
git push
