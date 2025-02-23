#!/bin/bash
# Run this from the main folder

docker rm -f surveyor

docker build --platform linux/arm64 -t docker-image:surveyor -f Dockerfile .

docker run --name surveyor --platform linux/arm64 -p 9000:8080 docker-image:surveyor

export SURVEYOR_URL="http://localhost:9000/2015-03-31/functions/function/invocations"