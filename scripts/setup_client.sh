#!/bin/bash -e

KEYFILE=$1
IP=$2
COORDINATOR_IP=$3
PARTICIPATION_MODE=$4

export COMMIT="main"

ssh -i "$KEYFILE" -o LogLevel=quiet -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
touch .hushlogin
ENDSSH

echo Setting up client

ADDRESS=$(ssh -i "$KEYFILE" -o LogLevel=quiet -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v
{
  sudo apt update
  sudo apt install -y tmux build-essential jq
  curl https://sh.rustup.rs -sSf | sh -s -- -y

  export PATH="\$HOME/.cargo/bin:\$PATH"

  rm -rf snark-setup-operator
  git clone https://github.com/celo-org/snark-setup-operator
  cd snark-setup-operator
  git checkout $COMMIT
  cargo build --release --bin generate
  echo test | ./target/release/generate --unsafe-passphrase
  cargo build --release --bin contribute

  tmux kill-server || true
  echo "echo test | RUST_LOG=info ./target/release/contribute --unsafe-passphrase --coordinator-url http://$COORDINATOR_IP --participation-mode $PARTICIPATION_MODE" > run_client.sh
  chmod +x run_client.sh
  tmux new-session -d -s contributor ./run_client.sh
} 2>/dev/null 1>/dev/null
cat plumo.keys | jq '.address' -r
set +e
exit 0
ENDSSH
)

echo $ADDRESS >> ${PARTICIPATION_MODE}_addresses

echo Set up client

exit 0
