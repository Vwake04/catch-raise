#!/bin/sh

if [ -z "$SSH_B64_PRIVATE_KEY" ]; then
  echo "The SSH_B64_PRIVATE_KEY is not set"
  exit 1
fi

if [ -z "$SSH_PUBLIC_KEY" ]; then
  echo "The SSH_PUBLIC_KEY is not set"
  exit 1
fi