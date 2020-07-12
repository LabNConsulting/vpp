#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
SHELL := /bin/bash
ifeq ($(CI_REGISTRY),)
BUILDIMAGE ?= labn/docker-ci-test:18.04
else
BUILDIMAGE ?= $(CI_REGISTRY)/labn/docker-ci-test:18.04
endif
USERID := $(shell id -u)
GROUPID := $(shell id -g)

# git clone https://github.com/LabNConsulting/docker-ci-test.git in parent of
# vpp root.
BUILDIMAGESRC ?= ../../docker-ci-test

VPP_DIR := $(shell realpath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SWAN_DIR := $(shell realpath $(dir $(lastword $(MAKEFILE_LIST)))/../../strongswan)
HOSTNAME := $(shell hostname)

DOCKRUN := docker run -i -v $(SWAN_DIR):$(SWAN_DIR) -v $(VPP_DIR):$(VPP_DIR) --user=$(USERID):$(GROUPID) $(BUILDIMAGE)
DOCKTEST := docker run -i --privileged --shm-size=512m -v /dev/hugepages:/dev/hugepages -v $(VPP_DIR):$(VPP_DIR) --user=$(USERID):$(GROUPID) $(BUILDIMAGE)

# Need a better way to do this.
ifeq ($(DEBUG),1)
TESTTAG ?= -debug
TARGETTAG ?=
BLDTAG ?= _debug
else
TESTTAG ?=
TARGETTAG ?= -release
BLDTAG ?=
endif

TBDATA_FILE := /etc/vpp-lab-data/testbed_data.json
ifneq ("$(wildcard $(TBDATA_FILE))","")
ifneq ("$(shell grep testbed_machines $(TBDATA_FILE))","")
USE_DOCKER ?= 0
else
USE_DOCKER ?= 1
endif
else
USE_DOCKER ?= 1
endif

ifeq ($(ASAN),1)
ASAN_MK := VPP_EXTRA_CMAKE_ARGS=-DVPP_ENABLE_SANITIZE_ADDR=ON
else
ASAN_MK :=
endif

VPPBLDDIR=$(VPP_DIR)/build-root/build-vpp$(BLDTAG)-native
SWANBLDDIR=$(VPP_DIR)/build-root/build-vpp$(BLDTAG)-native/vpp/strongswan
VPPINSTDIR=$(VPP_DIR)/build-root/install-vpp$(BLDTAG)-native/vpp

SWAN_CFG_CFLAGS := -g -O0 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign
SWANCONFARGS := --prefix=$(VPPINSTDIR) --disable-kernel-netlink --disable-systemd \
		--with-systemdsystemunitdir=$(VPPINSTDIR)/lib/systemd/system \
		--enable-kernel-vpp --enable-socket-vpp --enable-kernel-libipsec --enable-gcm
SWANAUTOCONF := (cd $(SWAN_DIR) && autoreconf -i) && \
    ( mkdir -p $(SWANBLDDIR) && \
      cd $(SWANBLDDIR) && \
      CFLAGS="$(SWAN_CFG_CFLAGS)" $(SWAN_DIR)/configure $(SWANCONFARGS))


ifeq ($(USE_DOCKER),0)
# used for syncing the git repo to all local testing boxes
sync-rule = time ./rsync-repo.sh ${VPP_DIR}
swan-sync-rule = [[ -d $(SWAN_DIR) ]] && time ./rsync-repo.sh ${SWAN_DIR}
else
sync-rule = echo "nosync"
swan-sync-rule = [[ -d $(SWAN_DIR) ]] && echo "nosync"
endif

ifeq ($(USE_DOCKER),0)
swan-autoconf-rule =	$(SWANAUTOCONF)
swan-build-rule = (cd $(SWANBLDDIR) && make all)
swan-install-rule = (cd $(SWANBLDDIR) && make install)
build-rule = (cd .. && make $(ASAN_MK) -j 16 build$(TARGETTAG))
else
swan-autoconf-rule = $(DOCKRUN) bash -c '$(SWANAUTOCONF)'
swan-build-rule = $(DOCKRUN) bash -c '(cd $(SWANBLDDIR) && make all)'
swan-install-rule = $(DOCKRUN) bash -c '(cd $(SWANBLDDIR) && make install)'
build-rule = $(DOCKRUN) bash -c "cd $(VPP_DIR) && make $(ASAN_MK) -j 16 build$(TARGETTAG)"
pkg-rule = $(DOCKRUN) bash -c "cd $(VPP_DIR) && make $(ASAN_MK) -j 16 pkg-deb"
smoke-test-rule = $(DOCKTEST) bash -c "cd $(VPP_DIR) && make $(ASAN_MK) -j 16 test$(TESTTAG) TEST=iptfs"
all-test-rule = $(DOCKTEST) bash -c "cd $(VPP_DIR) && make $(ASAN_MK) -j 16 test$(TESTTAG)"
endif

wipe:
	(cd .. && make wipe wipe-release)

build-deb:
	$(call pkg-rule)

# Below is not used by CI.

build-no-sync:
	$(call build-rule)
	(cd .. && ln -fs build-root/build-vpp$(BLDTAG)-native/vpp/compile_commands.json .)

build: build-no-sync
	$(call sync-rule)

build+swan: build-no-sync
	$(call swan-build-rule)
	$(call swan-install-rule)
	$(call swan-sync-rule)
	$(call sync-rule)

build+swan+autoconf: build-no-sync
	$(call swan-autoconf-rule)
	$(call swan-build-rule)
	$(call swan-install-rule)
	$(call swan-sync-rule)
	$(call sync-rule)

sync:
	$(call swan-sync-rule)
	$(call sync-rule)

smoke-test: build-no-sync
	$(call smoke-test-rule)

all-test: build-no-sync
	$(call all-test-rule)

# For local building w/o access to gitlab.
build-builder:
	docker build -t $(BUILDIMAGE) $(BUILDIMAGESRC)

build-ext-deps:
	(cd $(VPPSRC) && docker run -i -v $$(pwd):$$(pwd) --user=$(USERID) $(BUILDIMAGE) bash -c "cd $$(pwd) && ls && make i$
