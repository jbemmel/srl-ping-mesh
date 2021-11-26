ARG BASE_IMAGE=ghcr.io/nokia/srlinux
ARG SR_LINUX_RELEASE=latest

FROM centos:8 AS builder
RUN yum install -y gcc-c++ python3 git && python3 -m pip install -U pip wheel

# create scapy wheel (need latest version to fix some scapy bugs)
RUN git clone https://github.com/secdev/scapy && \
    PYTHONDONTWRITEBYTECODE=1 python3 -m pip wheel --no-cache-dir --wheel-dir=/tmp/wheels ./scapy/

# create wheels for rest of dependencies
RUN python3 -m pip wheel --no-cache-dir --wheel-dir=/tmp/wheels \
    https://github.com/nokia/srlinux-ndk-py/archive/v21.6.2.zip \
    netns \
    pygnmi


FROM $BASE_IMAGE:$SR_LINUX_RELEASE AS target-image
ARG APP_NAME=bgp-ping-mesh
ARG VENV=/opt/${APP_NAME}/.venv

# Create a Python virtual environment, don't use '--upgrade' else no 'activate' script
RUN sudo python3 -m venv $VENV && source $VENV/bin/activate && python3 -m pip install -U pip wheel

# copy wheels from builder and install them
COPY --from=builder /tmp/wheels /tmp/wheels
RUN source $VENV/bin/activate && python3 -m pip install --no-cache --no-index /tmp/wheels/*

RUN sudo mkdir --mode=0755 -p /etc/opt/srlinux/appmgr/
COPY --chown=srlinux:srlinux ./bgp-ping-mesh.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/

# run pylint to catch any obvious errors
# TODO: (rdodin) I haven't installed pylint in the venv, it can be fetched from some other place
RUN bash -c "(which pylint && PYTHONPATH=$VIRTUAL_ENV/lib/python3.6/site-packages:$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/bgp-ping-mesh) || true"

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_BGP_PING_MESH_RELEASE="[custom build]"
ENV SRL_BGP_PING_MESH_RELEASE=$SRL_BGP_PING_MESH_RELEASE
