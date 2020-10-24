#!/bin/bash -e

KEYFILE=$1
COORDINATOR_IP=$(cat server_ip)
OPERATOR_IP=$(cat operator_ip)

POWERS=15
CHUNK_SIZE=10

function wait_and_get_exit_codes() {
    children=("$@")
    EXIT_CODE=0
    for job in "${children[@]}"; do
       echo "PID => ${job}"
       CODE=0;
       wait ${job} || CODE=$?
       if [[ "${CODE}" != "0" ]]; then
           echo "At least one test failed with exit code => ${CODE}" ;
           exit 1
       fi
   done
}

./setup_server.sh "$KEYFILE" $COORDINATOR_IP

children_pids=()

rm -f contribute_addresses
while read p; do
  ./setup_client.sh "$KEYFILE" $p $COORDINATOR_IP contribute &
  children_pids+=("$!")
done < contributors_ips

rm -f verify_addresses
while read p; do
  ./setup_client.sh "$KEYFILE" $p $COORDINATOR_IP verify &
  children_pids+=("$!")
done < verifiers_ips

wait_and_get_exit_codes "${children_pids[@]}"

./setup_new_ceremony.sh "$KEYFILE" $OPERATOR_IP $COORDINATOR_IP $POWERS $CHUNK_SIZE
