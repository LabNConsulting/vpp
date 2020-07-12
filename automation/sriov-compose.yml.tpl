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
    PATH: ${VPPROOT}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

x-dutvols: &dutvols
  # This is used by memif not sure if we ever will get that working.
  - /tmp/run-vpp:/run/vpp/shared
  - /var/crash:/var/crash
  - /dev/hugepages:/dev/hugepages
  - /var/run/systemd/journal/socket:/var/run/systemd/journal/socket
  - /home/chopps/w/strongswan:/home/chopps/w/strongswan:ro
  - ${VPPDIR}:${VPPDIR}:ro
  - ../:/vpp:ro

services:
  sriovtrex:
    <<: *stdsvc
    image: labn/trex:v2.86
    hostname: trex
    networks:
      arex:
        # We need a (any) reachable address to talk to trex
      p1:
        ipv4_address: 11.11.11.253
      p2:
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
      p1:
        ipv4_address: 11.11.11.11
      p3:
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
      - /home/chopps/w/strongswan:/home/chopps/w/strongswan:ro
      - ${VPPDIR}:${VPPDIR}:ro
      - ../:/vpp:ro

  d2:
    <<: *stdsvc
    <<: *stddut
    image: labn/docker-ci-test:18.04
    hostname: d2
    networks:
      arex:
        # We need a (any) reachable address to talk to gdb
      p2:
        ipv4_address: 12.12.12.12
      p3:
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
      - /home/chopps/w/strongswan:/home/chopps/w/strongswan:ro
      - ${VPPDIR}:${VPPDIR}:ro
      - ../:/vpp:ro

networks:
  # arex is a network used to reach trex
  arex:
  p1:
    internal: true
    driver: sriov
    driver_opts:
      netdevice: "ens16f0"
      privileged: "1"
      vlan: "11"
    ipam:
      config:
        - subnet: 11.11.11.0/24
  p2:
    internal: true
    driver: sriov
    driver_opts:
      netdevice: "ens16f0"
      privileged: "1"
      vlan: "12"
    ipam:
      config:
        - subnet: 12.12.12.0/24
  p3:
    internal: true
    driver: sriov
    driver_opts:
      netdevice: "ens16f1"
      privileged: "1"
    ipam:
      config:
        - subnet: 13.13.13.0/24
