#!/bin/bash -e

KEYFILE=$1
COORDINATOR_IP=$(cat server_ip)
OPERATOR_IP=$(cat operator_ip)

POWERS=27
CHUNK_SIZE=20

retry() {
    local -r -i max_attempts="$1"; shift
    local -r cmd="$@"
    local -i attempt_num=1

    until $cmd
    do
        if (( attempt_num == max_attempts ))
        then
            echo "Attempt $attempt_num for command $cmd failed and there are no more attempts left!"
            return 1
        else
            echo "Attempt $attempt_num for command $cmd failed! Trying again in $attempt_num seconds..."
            sleep $(( attempt_num++ ))
        fi
    done
}

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
