#ifndef UTILS_H
#define UTILS_H

#include <glib.h>
#include <stdio.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip6.h>

#include <systemd/sd-bus.h>

#include "connman-1.32/gdhcp/common.h"

#include <time.h>
#include <sys/types.h>

#define MAX_PACKETS 5

typedef enum
{
    PACKET_IPV4,
    PACKET_IPV6
} packet_type_t;

typedef struct __attribute__((packed)) frame
{
    struct ether_header eth_hdr;
    struct ip_udp_dhcp_packet ip_udp_dhcp;
} frame_t;

struct ip_udp_dhcpv6_packet
{
    struct ip6_hdr ip;
    struct udphdr udp;
    struct dhcpv6_packet dhcpv6;
};

typedef struct __attribute__((packed)) framev6
{
    struct ether_header eth_hdr;
    struct ip_udp_dhcpv6_packet ip_udp_dhcp;
} framev6_t;

typedef struct
{
    packet_type_t type;
    union
    {
        frame_t v4;
        framev6_t v6;

    } pkt;
} packet_t;

const char *dhcpv4_msg_to_str(uint8_t type);
const char *dhcpv6_msg_to_str(uint8_t type);

#endif