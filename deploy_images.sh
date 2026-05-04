#!/bin/bash

DOCKER_USER="zak19"
BASE_TAG="3.1-dev"

UBUNTU_VER="24.04"
TARGETOS="linux"
TARGETARCH="amd64"
FABRIC_VER="3.1-dev"
GO_VER="1.26.2"
GO_TAGS=""

COMPONENTS=("baseos" "ccenv" "orderer" "peer" "tools")

echo "🚀 [1/2] Starting Multi-stage compilation via Dockerfiles of Fabric..."

for COMPONENTE in "${COMPONENTS[@]}"; do
    echo -e "\n--------------------------------------------------------"
    echo "🔨 Building Image: $DOCKER_USER/fabric-$COMPONENTE:$BASE_TAG"
    echo "--------------------------------------------------------"
    
    sudo docker build \
        --build-arg UBUNTU_VER=$UBUNTU_VER \
        --build-arg TARGETOS=$TARGETOS \
        --build-arg TARGETARCH=$TARGETARCH \
        --build-arg FABRIC_VER=$FABRIC_VER \
        --build-arg GO_VER=$GO_VER \
        --build-arg GO_TAGS=$GO_TAGS \
        -f images/${COMPONENTE}/Dockerfile \
        -t $DOCKER_USER/fabric-${COMPONENTE}:$BASE_TAG \
        .
        
    if [ $? -ne 0 ]; then
        echo "❌ Critical Error while building component $COMPONENTE. Aborting pipeline."
        exit 1
    fi
done

echo -e "\n========================================================"
echo "☁️ [2/2] Pushing images to docker hub..."
echo "========================================================"

for COMPONENTE in "${COMPONENTS[@]}"; do
    echo "Enviando $DOCKER_USER/fabric-${COMPONENTE}:$BASE_TAG ..."
    sudo docker push $DOCKER_USER/fabric-${COMPONENTE}:$BASE_TAG
done

echo -e "\n✅ All images built and pushed sucessfully!"