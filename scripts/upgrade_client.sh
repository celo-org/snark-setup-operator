#!/bin/bash -e

KEYFILE=$1
IP=$2
COORDINATOR_IP=$3
PARTICIPATION_MODE=$4

export COMMIT="feat/setup_scripts"

echo Upgrading client

ssh -i "$KEYFILE" -o LogLevel=quiet -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v
{
  export PATH="\$HOME/.cargo/bin:\$PATH"

  cd snark-setup-operator
  git pull
  git checkout $COMMIT
  cargo build --release --bin contribute

  tmux kill-server || true
  echo "echo test | RUST_LOG=info ./target/release/contribute --unsafe-passphrase --coordinator-url http://$COORDINATOR_IP --participation-mode $PARTICIPATION_MODE" > run_client.sh
  chmod +x run_client.sh
  tmux new-session -d -s contributor ./run_client.sh
} 2>/dev/null 1>/dev/null
ENDSSH

echo Upgraded client

exit 0
