#!/bin/bash -e

KEYFILE=$1
IP=$2
PARTICIPATION_MODE=$3

export COMMIT="feat/setup_scripts"

echo Restarting client

ssh -i "$KEYFILE" -o LogLevel=quiet -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
  tmux kill-server || true
  tmux new-session -d -s contributor ./run_client.sh
ENDSSH

echo Restarted client

exit 0
