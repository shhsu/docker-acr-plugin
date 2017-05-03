#!/bin/bash
set -e

script_root="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $script_root/../docker-login-acr
go build
cd $script_root/../login-config-editor
go build
