#!/bin/bash

TOP_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";

echo Stoping the topology
cd $TOP_DIR/network
export DIST=$TOP_DIR
docker compose down
