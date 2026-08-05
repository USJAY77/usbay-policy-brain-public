#!/usr/bin/env bash
# Persistent GIT_ASKPASS helper for USBAY-GLOBAL org pushes.
# Reads GITHUB_TOKEN from the environment at runtime — never writes it to disk.
# Git calls this script with the prompt text as $1:
#   "Username for 'https://github.com':"  → x-access-token
#   "Password for 'https://...'"          → $GITHUB_TOKEN
case "$1" in
  Username*) echo "x-access-token" ;;
  Password*) echo "${GITHUB_TOKEN}" ;;
  *)         echo "" ;;
esac
