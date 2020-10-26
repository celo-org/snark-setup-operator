#!/bin/bash -e

KEYFILE=$1
COORDINATOR_IP=$(cat server_ip)
OPERATOR_IP=$(cat operator_ip)

POWERS=27
CHUNK_SIZE=20

. ./utils.sh

retry 5 ./setup_server.sh "$KEYFILE" $COORDINATOR_IP

children_pids=()

rm -f contribute_addresses
while read p; do
  retry 5 ./setup_client.sh "$KEYFILE" $p $COORDINATOR_IP contribute &
  children_pids+=("$!")
done < contributors_ips

rm -f verify_addresses
while read p; do
  retry 5 ./setup_client.sh "$KEYFILE" $p $COORDINATOR_IP verify &
  children_pids+=("$!")
done < verifiers_ips

wait_and_get_exit_codes "${children_pids[@]}"

retry 5 ./setup_new_ceremony.sh "$KEYFILE" $OPERATOR_IP $COORDINATOR_IP $POWERS $CHUNK_SIZE
