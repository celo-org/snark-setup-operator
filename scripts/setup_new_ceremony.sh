#!/bin/bash -e

KEYFILE=$1
IP=$2
COORDINATOR_IP=$3
POWERS=$4
CHUNK_SIZE=$5
STORAGE_KEY=$(cat storage_access_key)

export COMMIT="main"
export VERIFIER_KEYS=$(cat ../e2e/plumo-verifier.keys)
export CONTRIBUTORS=""
export VERIFIERS=""

while read p; do
  CONTRIBUTORS="$CONTRIBUTORS --participant $p"
done < contribute_addresses

while read p; do
  VERIFIERS="$VERIFIERS --verifier $p"
done < verify_addresses

ssh -i "$KEYFILE" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v

sudo apt update
sudo apt install -y tmux build-essential jq
curl https://sh.rustup.rs -sSf | sh -s -- -y

export PATH="\$HOME/.cargo/bin:\$PATH"

rm -rf snark-setup-operator
git clone https://github.com/celo-org/snark-setup-operator
cd snark-setup-operator
git checkout $COMMIT
cargo build --release --bin new_ceremony

tmux kill-server || true
echo '$VERIFIER_KEYS' > plumo.keys
echo "echo 1 | RUST_LOG=info ./target/release/new_ceremony --unsafe-passphrase --upload-mode azure --storage-account optimisticstorage --container chunks --access-key $STORAGE_KEY --chunk-size $CHUNK_SIZE --powers $POWERS $CONTRIBUTORS $VERIFIERS --server-url http://$COORDINATOR_IP" > run_new_ceremony.sh
chmod +x run_new_ceremony.sh
tmux new-session -d -s new-ceremony ./run_new_ceremony.sh
set +e
exit 0
ENDSSH

exit 0
