#!/bin/bash -e

KEYFILE=$1
COORDINATOR_IP=$(cat server_ip)

children_pids=()

while read p; do
  retry 5 ./restart_client.sh "$KEYFILE" $p contribute &
  children_pids+=("$!")
done < contributors_ips

while read p; do
  retry 5 ./restart_client.sh "$KEYFILE" $p verify &
  children_pids+=("$!")
done < verifiers_ips

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

wait_and_get_exit_codes "${children_pids[@]}"
