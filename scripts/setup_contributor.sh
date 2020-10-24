#!/bin/bash -e

KEYFILE=$1
IP=$2
COORDINATOR_IP=$3

export COMMIT="master"

ADDRESS=$(ssh -i "$KEYFILE" -t -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v

sudo apt update
sudo apt install -y tmux build-essential
curl https://sh.rustup.rs -sSf | sh -s -- -y
rustup install stable

export PATH="\$HOME/.cargo/bin:\$PATH"

rm -rf snark-setup-operator
git clone https://github.com/celo-org/snark-setup-operator
cd snark-setup-operator
cargo build --release --bin generate
echo test | ./target/release/generate --unsafe-passphrase
cargo build --release --bin contribute

tmux new-session -d -s contributor "echo test | ./target/release/contribute --unsafe-passphrase --coordinator-url $COORDINATOR_IP"
cat plumo.keys | jq '.address' -r
ENDSSH
)

echo "GOT ADDRESS: $ADDRESS"