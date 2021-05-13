#!/bin/bash

OS=$1

pushd $(dirname "$0")/../build
  mkdir -p out
  docker build --tag=snark-setup-operator-cross-compile -f Dockerfile-${OS} ..
  docker create --name=snark-setup-operator-cross-compile snark-setup-operator-cross-compile
  docker cp snark-setup-operator-cross-compile:/usr/src/main/out .
  docker rmi -f snark-setup-operator-cross-compile
  docker rm -f snark-setup-operator-cross-compile
popd