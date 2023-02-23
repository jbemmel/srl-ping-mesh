NAME        := srl/bgp-ping-mesh
LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
IMG         := ${NAME}:${TAG}
LATEST      := ${NAME}:latest
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

ifndef SR_LINUX_RELEASE
override SR_LINUX_RELEASE="latest"
endif

container-image: BASE_IMAGE = srl/custombase
container-image: build

build:
	echo ${TAG} > src/bgp-ping-mesh/agent_version
	sudo docker build --build-arg SRL_BGP_PING_MESH_RELEASE=${TAG} \
	                  --build-arg http_proxy=${HTTP_PROXY} \
										--build-arg https_proxy=${HTTP_PROXY} \
										--build-arg BASE_IMAGE=${BASE_IMAGE} \
	                  --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	                  -f ./Dockerfile -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

build-submodules:
	make -C srl-baseimage

all: build-submodules build

CREATE_CONTAINER := $(shell docker create ${LATEST})
SET_CONTAINER_ID = $(eval CONTAINER_ID=$(CREATE_CONTAINER))

rpm: BASE_IMAGE = ghcr.io/nokia/srlinux
rpm: build
	mkdir -p rpmbuild
	$(SET_CONTAINER_ID)
	docker cp --follow-link ${CONTAINER_ID}:/opt/bgp-ping-mesh/ rpmbuild/
	docker rm ${CONTAINER_ID}
	find rpmbuild/ -type l -delete # Purge symlinks, including broken ones
	awk '/version/{print $$2}' fpmConfig.yml > rpmbuild/bgp-ping-mesh/agent_version
	docker run --rm -v ${PWD}:/tmp -w /tmp goreleaser/nfpm package \
    --config /tmp/fpmConfig.yml \
    --target /tmp \
    --packager rpm
	# rm -rf rpmbuild
