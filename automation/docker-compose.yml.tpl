# -*- mode:yaml -*-
version: "2.4"

x-stdcap: &stdcap
  cap_add:
    - ALL
    # - IPC_LOCK
    # - NET_ADMIN
    # - SYS_ADMIN
    # - SYS_PTRACE
    # - SYS_NICE                  # set_mempriority

x-stdsys: &stdsysctl
  sysctls:
    - net.ipv6.conf.all.disable_ipv6=1
    - net.ipv6.conf.all.forwarding=1
    - net.ipv6.conf.default.forwarding=1

x-stdsvc: &stdsvc
  <<: *stdcap
  <<: *stdsysctl
  command: bash -c "groupadd vpp --gid=${USERGID}; tail -f /dev/null"
  privileged: true

x-stddut: &stddut
  ulimits:
    core: "-1"
  environment:
    PATH: "${VPPROOT}/bin:${VPPROOT}/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    LD_LIBRARY_PATH: "${VPPLDPATH}"

services:
  trex:
    <<: *stdsvc
    image: labn/trex:v2.86
    hostname: trex
    networks:
      arex:
        # We need a (any) reachable address to talk to trex
      p0:
        ipv4_address: 11.11.11.253
      p1:
        ipv4_address: 12.12.12.253
    ports:
      - 8090:8090
      - 4500:4500
      - 4501:4501
    volumes:
      - /dev/hugepages:/dev/hugepages
      - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
      - ../:/vpp:ro
  d1:
    <<: *stdsvc
    <<: *stddut
    image: labn/docker-ci-test:18.04
    hostname: d1
    networks:
      arex:
        # We need a (any) reachable address to talk to gdb
      p0:
        ipv4_address: 11.11.11.11
      p2:
        ipv4_address: 13.13.13.11
    ports:
      - "5011:5011"
    volumes:
      - /tmp/vpp-run-d1:/run
      # This is used by memif not sure if we ever will get that working.
      - /tmp/run-vpp:/run/vpp/shared
      - /var/crash:/var/crash
      - /dev/hugepages:/dev/hugepages
      - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
      - ${VPPDIR}/../strongswan:/home/chopps/w/strongswan:ro
      # For ike we have to mount R/W
      - ${VPPDIR}:${VPPDIR}
      - ../:/vpp:ro

  d2:
    <<: *stdsvc
    <<: *stddut
    image: labn/docker-ci-test:18.04
    hostname: d2
    networks:
      arex:
        # We need a (any) reachable address to talk to gdb
      p1:
        ipv4_address: 12.12.12.12
      p2:
        ipv4_address: 13.13.13.12
    ports:
      - "5012:5012"
    volumes:
      - /tmp/vpp-run-d2:/run
      # This is used by memif not sure if we ever will get that working.
      - /tmp/run-vpp:/run/vpp/shared
      - /var/crash:/var/crash
      - /dev/hugepages:/dev/hugepages
      - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
      - ${VPPDIR}/../strongswan:/home/chopps/w/strongswan:ro
      # For ike we have to mount R/W
      - ${VPPDIR}:${VPPDIR}
      - ../:/vpp:ro

networks:
  # arex is a network used to reach trex
  arex:
  p0:
    # driver: "choppsv1/docker-network-p2p:1.2"
    ipam:
      config:
        - subnet: 11.11.11.0/24
  p1:
    # driver: "choppsv1/docker-network-p2p:1.2"
    ipam:
      config:
        - subnet: 12.12.12.0/24
  p2:
    # We need a tap-able interface here so use normal veth
    # driver: "choppsv1/docker-network-p2p:1.2"
    ipam:
      config:
        - subnet: 13.13.13.0/24
