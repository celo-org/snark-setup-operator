#!/bin/bash -e

SSH_KEY=$1
AMOUNT_CONTRIBUTORS=$2
AMOUNT_VERIFIERS=$3

GROUP=optimistic-test
VM_SIZE=Standard_D8d_v4

rm -f contributors_ips
touch contributors_ips
rm -f verifiers_ips
touch verifiers_ips
rm -f storage_access_key
rm -f server_ip
rm -f operator_ip

az group create -n $GROUP -l eastus
az storage account create -g $GROUP -n optimisticstorage
az storage account keys list -g $GROUP -n optimisticstorage | jq '.[0].value' -r > storage_access_key
az vm create -g $GROUP -n optimistic-server --admin-username azureuser --image UbuntuLTS --ssh-key-values $SSH_KEY --size $VM_SIZE
IP=$(az vm show -g $GROUP -n optimistic-server -d | jq '.publicIps' -r)
echo $IP >> server_ip
az vm open-port --port 80 -g $GROUP -n optimistic-server

az vm create -g $GROUP -n optimistic-operator --admin-username azureuser --image UbuntuLTS --ssh-key-values $SSH_KEY --size $VM_SIZE
IP=$(az vm show -g $GROUP -n optimistic-operator -d | jq '.publicIps' -r)
echo $IP >> operator_ip

for i in $(seq 1 $AMOUNT_CONTRIBUTORS)
do
  az vm create -g $GROUP -n optimistic-contributor-$i --admin-username azureuser --image UbuntuLTS --ssh-key-values $SSH_KEY --size $VM_SIZE
  IP=$(az vm show -g $GROUP -n optimistic-contributor-$i -d | jq '.publicIps' -r)
  echo $IP >> contributors_ips
done

for i in $(seq 1 $AMOUNT_VERIFIERS)
do
  az vm create -g $GROUP -n optimistic-verifier-$i --admin-username azureuser --image UbuntuLTS --ssh-key-values $SSH_KEY --size $VM_SIZE
  IP=$(az vm show -g $GROUP -n optimistic-verifier-$i -d | jq '.publicIps' -r)
  echo $IP >> verifiers_ips
done
