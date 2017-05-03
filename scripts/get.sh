#!/bin/bash
set -e

configFileLocation=$HOME/.docker/config.json
blobSource="https://aadacr.blob.core.windows.net/binaries/"

while getopts ":e:c:" opt; do
    case $opt in
        e) installLocation="$OPTARG"
        ;;
        c) configFileLocation="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2
        ;;
    esac
done

if [ -z "$installLocation" ]; then
    printf "Please provide a location to download your files. Or press enter to use the current directory:\n"
    read installLocation
    if [ -z "$installLocation" ]; then
        installLocation=`pwd`
    else
        mkdir -p $installLocation
    fi
fi

if [ "$blobSource" != */ ]; then
    blobSource="$blobSource/"
fi

for file in "docker dockerd docker-login-acr login-config-editor"; do
    curl -O "${installLocation}/${file}" "${blobSource}${file}"
    chmod +x "${installLocation}/${file}"
done

if [ ! -z "$configFileLocation" ]; then
    configFileOption="--config-file $configFileLocation"
fi

$installLocation/login-config-editor --module "acr" --challenge-type "Bearer" --challenge-realm "https://*.azurecr.io/oauth2/token"  $configFileOption
export PATH=$installLocation:$PATH
