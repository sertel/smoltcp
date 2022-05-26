#!/bin/bash
: '
Script to create tap interface for smolTCP testing. 
First parameter ($1) is the user to create the interface for.
'
ip tuntap add name tap0 mode tap user $1
ip link set tap0 up
ip addr add 192.168.69.100/24 dev tap0
ip link set address 02:00:00:00:00:02 dev tap0
ip -6 addr add fe80::100/64 dev tap0
ip -6 addr add fdaa::100/64 dev tap0
ip -6 route add fe80::/64 dev tap0
ip -6 route add fdaa::/64 dev tap0


iptables -t nat -A POSTROUTING -s 192.168.69.0/24 -j MASQUERADE
sysctl net.ipv4.ip_forward=1
ip6tables -t nat -A POSTROUTING -s fdaa::/64 -j MASQUERADE
sysctl -w net.ipv6.conf.all.forwarding=1


iptables -A FORWARD -i tap0 -s 192.168.69.0/24 -j ACCEPT
iptables -A FORWARD -o tap0 -d 192.168.69.0/24 -j ACCEPT

