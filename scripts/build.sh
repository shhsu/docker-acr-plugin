#!/bin/bash
set -e

targetDir=`pwd`
dockerRepo="https://github.com/shhsu/docker.git"
dockerBranch="azure_login_v2"
toolsRepo="https://github.com/shhsu/docker-acr-plugin.git"
toolsBranch="no_challenge"

while getopts ":t:" opt; do
    case $opt in
        t) targetDir="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2
        ;;
    esac
done

function DeleteOutput() {
    if [ -e $1 ]; then
        rm $1
    fi
    if [ -d $1 ]; then
        rm -r -f $1
    fi
}

function Cleanup() {
    ## note that this filter is not a exact match, anything with this substring is matched
    if [ ! -z "`docker ps -a --filter=name=$buildContainer | grep $buildContainer`" ]; then
    	docker rm -f $buildContainer
    fi

    if [ ! -z "`docker images $buildImage | grep $buildImage`" ]; then
	    docker rmi -f $buildImage
    fi

    if [ -d $workspace ]; then
         rm -r -f $workspace
    fi
}

buildContainer="acrloginbuild"
buildImage="acrloginbuildimg"	## This image is used for building docker
workspace="`pwd`/ACR_DOCKER_BUILD"

if [ ! -d $targetDir ]; then
    mkdir -p $targetDir
fi

Cleanup
DeleteOutput "docker-login-acr"
DeleteOutput "docker"

mkdir $workspace
git clone $dockerRepo -b $dockerBranch $workspace/docker
pushd $workspace/docker
make
popd

cp $workspace/docker/bundles/latest/binary-client/docker $targetDir
cp $workspace/docker/bundles/latest/binary-daemon/dockerd $targetDir

## build tools
git clone $toolsRepo -b $toolsBranch $workspace/docker-acr-plugin
docker run --name $buildContainer -e DOCKER_GITCOMMIT=$DOCKER_GITCOMMIT -v $workspace/docker-acr-plugin:/go/src/github.com/docker-acr-plugin --privileged golang /go/src/github.com/docker-acr-plugin/scripts/build-tools.sh

docker cp ${buildContainer}:/go/src/github.com/docker-acr-plugin/docker-login-acr/docker-login-acr $targetDir
docker cp ${buildContainer}:/go/src/github.com/docker-acr-plugin/login-config-editor/login-config-editor $targetDir
docker cp ${buildContainer}:/go/src/github.com/docker-acr-plugin/scripts/get.sh $targetDir

echo "The following files are published"
ls $targetDir
pushd $targetDir
echo "To Directory: "`pwd`
popd

## Note that because we are running docker build with elevated mode, we can't really remove the binaries built unless we are running as super user
## Therefore the script would skip cleanup to avoid error
# Cleanup
