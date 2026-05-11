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
#include <sys/ioctl.h>

#include <linux/if_packet.h>
#include <net/if.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <systemd/sd-bus.h>

#include "connman-1.32/gdhcp/common.h"

#include <time.h>
#include <sys/types.h>

#define MAX_PACKETS 5
#define MAX_TIMEOUT_BREAK 7
#define MAX_FRAME_SIZE 1514

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

struct __attribute__((packed)) ip_udp_dhcpv6_packet
{
    struct ip6_hdr ip;
    struct udphdr udp;
    struct dhcpv6_packet dhcpv6;
};

typedef struct __attribute__((packed)) framev6
{
    struct ether_header eth_hdr;
    union
    {
        struct ip_udp_dhcpv6_packet ip_udp_dhcp;
        struct
        {
            struct ip6_hdr ip6;
            struct icmp6_hdr icmp6;
        } ip_icmp;
    } payload;
} framev6_t;

typedef struct
{
    packet_type_t type;
    uint64_t len;
    union
    {
        frame_t v4;
        framev6_t v6;

    } pkt;
} packet_t;

const char *dhcpv4_msg_to_str(uint8_t type);
const char *dhcpv6_msg_to_str(uint8_t type);
int replace_dhcpv6_option(framev6_t *pkg, size_t *pkg_len, uint16_t opt_code, uint8_t *opt_data, uint16_t opt_len);
uint16_t udp6_checksum(struct ip6_hdr *ip6, struct udphdr *udp, uint8_t *payload, size_t payload_len);
void setup_veth_interfaces();
packet_t *parse_pcap(const char *pcap_path, size_t *out_count);
void debug(const char *format, ...);
char *wait_connmand(sd_bus *bus);
int enable_ethernet_tethering(sd_bus *bus);
int wait_for_tether_interface();

#endif