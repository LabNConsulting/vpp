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
  # ptrex:
  #   <<: *stdsvc
  #   image: labn/trex:v2.86
  #   hostname: ptrex
  #   networks:
  #     arex:
  #       # We need a (any) reachable address to talk to trex
  #   ports:
  #     - 8090:8090
  #     - 4500:4500
  #     - 4501:4501
  #   volumes:
  #     - /dev/hugepages:/dev/hugepages
  #     - /dev/vfio:/dev/vfio
  #     - /sys/bus/pci:/sys/bus/pci
  #     - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
  #     - ../:/vpp:ro
  pm1:
    <<: *stdsvc
    <<: *stddut
    image: labn/docker-ci-test:18.04
    hostname: pm1
    networks:
      arex:
        # We need a (any) reachable address to talk to gdb
    ports:
      - '5011:5011'
    volumes:
      - /dev/hugepages:/dev/hugepages
      - /dev/vfio:/dev/vfio
      - /tmp/vpp-run-pm1:/run
      # This is used by memif not sure if we ever will get that working.
      - /tmp/vpp-run-shared:/run/vpp/shared
      - /var/crash:/var/crash
      - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
      - ${VPPDIR}/../strongswan:/home/chopps/w/strongswan:ro
      # For ike we have to mount R/W
      - ${VPPDIR}:${VPPDIR}
      - ../:/vpp:ro

  pm2:
    <<: *stdsvc
    <<: *stddut
    image: labn/docker-ci-test:18.04
    hostname: pm2
    networks:
      arex:
        # We need a (any) reachable address to talk to gdb
    ports:
      - '5012:5012'
    volumes:
      - /dev/hugepages:/dev/hugepages
      - /dev/vfio:/dev/vfio
      - /tmp/vpp-run-pm2:/run
      # This is used by memif not sure if we ever will get that working.
      - /tmp/vpp-run-shared:/run/vpp/shared
      - /var/crash:/var/crash
      - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
      - ${VPPDIR}/../strongswan:/home/chopps/w/strongswan:ro
      # For ike we have to mount R/W
      - ${VPPDIR}:${VPPDIR}
      - ../:/vpp:ro

networks:
  arex:
