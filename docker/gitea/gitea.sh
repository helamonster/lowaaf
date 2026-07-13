#!/usr/bin/env bash
#
#



VERSION=1.26
VARIANT=rootless



DUID=100999
DGID=100999


mkdir config data
sudo chown ${DUID}:${DGID}  config/ data/


docker pull gitea/gitea:${VERSION}-${VARIANT}

# check out source code:
# 
# git clone https://github.com/go-gitea/gitea.git
#

