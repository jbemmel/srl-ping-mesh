ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE AS target-image

# Create a Python virtual environment
RUN sudo python3 -m venv /opt/bgp-ping-mesh/.venv --system-site-packages --without-pip --upgrade
ENV VIRTUAL_ENV=/opt/bgp-ping-mesh/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install scapy library and netns packages
RUN sudo -E python3 -m pip install scapy netns

# Fix scapy bug
COPY scapy/sendrecv.py /usr/local/lib/python3.6/site-packages/scapy/sendrecv.py

RUN sudo mkdir --mode=0755 -p /etc/opt/srlinux/appmgr/
COPY --chown=srlinux:srlinux ./bgp-ping-mesh.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/

# Add in auto-config agent sources too
# COPY --from=srl/auto-config-v2:latest /opt/demo-agents/ /opt/demo-agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/bgp-ping-mesh

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_BGP_PING_MESH_RELEASE="[custom build]"
ENV SRL_BGP_PING_MESH_RELEASE=$SRL_BGP_PING_MESH_RELEASE