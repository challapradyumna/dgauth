#!/bin/bash
# docker build . -t localhost:32000/dgauth
# docker push localhost:32000/dgauth
docker build . -f Dockerfile.playground -t localhost:32000/dgauth:playground
docker push localhost:32000/dgauth:playground
microk8s kubectl apply -f deploy.yaml
microk8s kubectl rollout restart deploy dgauth