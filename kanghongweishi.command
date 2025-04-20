#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
chmod +x kanghongweishi
sudo "$DIR/kanghongweishi"
