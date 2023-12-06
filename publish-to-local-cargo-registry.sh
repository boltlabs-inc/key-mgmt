# -e exits script if any command returns an error
set -e

CRATE_VERSION=$(sed -rn 's/^version = "(.+)"/\1/p' Cargo.toml)
echo Publishing version: $CRATE_VERSION

# Checkout main branch in the registry
cd key-mgmt-registry
git switch main
cd ..

# Build Lock Keeper and copy to local registry
cd lock-keeper
cargo index add \
    --index ../key-mgmt-registry \
    --index-url https://fake.com \
    --upload ../key-mgmt-registry/files/lock-keeper \
    -- \
    --allow-dirty

# Build Lock Keeper Client and copy to local registry
cd ../lock-keeper-client
cargo index add \
    --index ../key-mgmt-registry \
    --index-url https://fake.com \
    --upload ../key-mgmt-registry/files/lock-keeper-client \
    -- \
    --allow-dirty

# Push local registry
cd ../key-mgmt-registry
git add .
git commit -m "$CRATE_VERSION"
git push
