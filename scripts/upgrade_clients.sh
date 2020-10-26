#!/bin/bash -e

KEYFILE=$1
COORDINATOR_IP=$(cat server_ip)

. ./utils.sh

children_pids=()

while read p; do
  retry 5 ./upgrade_client.sh "$KEYFILE" $p $COORDINATOR_IP contribute &
  children_pids+=("$!")
done < contributors_ips

while read p; do
  retry 5 ./upgrade_client.sh "$KEYFILE" $p $COORDINATOR_IP verify &
  children_pids+=("$!")
done < verifiers_ips


wait_and_get_exit_codes "${children_pids[@]}"
