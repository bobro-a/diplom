#include "utils.h"

const char *dhcpv4_msg_to_str(uint8_t type)
{
    switch (type)
    {
    case DHCPDISCOVER:
        return "DHCP_DISCOVER";
    case DHCPOFFER:
        return "DHCP_OFFER";
    case DHCPREQUEST:
        return "DHCP_REQUEST";
    case DHCPDECLINE:
        return "DHCP_DECLINE";
    case DHCPACK:
        return "DHCP_ACK";
    case DHCPNAK:
        return "DHCP_NAK";
    case DHCPRELEASE:
        return "DHCP_RELEASE";
    case DHCPINFORM:
        return "DHCP_INFORM";
    default:
        return "UNKNOWN_DHCPV4";
    }
}

const char *dhcpv6_msg_to_str(uint8_t type)
{
    switch (type)
    {
    case 1:
        return "DHCPV6_SOLICIT";
    case 2:
        return "DHCPV6_ADVERTISE";
    case 3:
        return "DHCPV6_REQUEST";
    case 4:
        return "DHCPV6_CONFIRM";
    case 5:
        return "DHCPV6_RENEW";
    case 6:
        return "DHCPV6_REBIND";
    case 7:
        return "DHCPV6_REPLY";
    case 8:
        return "DHCPV6_RELEASE";
    case 9:
        return "DHCPV6_DECLINE";
    case 10:
        return "DHCPV6_RECONFIGURE";
    case 11:
        return "DHCPV6_INFORMATION_REQUEST";
    default:
        return "UNKNOWN_DHCPV6";
    }
}

int replace_dhcpv6_option(framev6_t *pkg, size_t *pkg_len, uint16_t opt_code, uint8_t *opt_data, uint16_t opt_len)
{
    uint8_t *options_start = (uint8_t *)pkg->payload.ip_udp_dhcp.dhcpv6.options;
    size_t options_len = *pkg_len - offsetof(framev6_t, payload.ip_udp_dhcp.dhcpv6.options);

    size_t offset = 0;
    uint8_t *opt_ptr = NULL;
    uint16_t old_len = 0;

    while (offset + 4 <= options_len)
    {
        uint16_t code = ntohs(*(uint16_t *)(options_start + offset));
        uint16_t len = ntohs(*(uint16_t *)(options_start + offset + 2));

        if (offset + 4 + len > options_len)
            break;

        if (code == opt_code)
        {
            opt_ptr = options_start + offset;
            old_len = len;
            break;
        }
        offset += 4 + len;
    }
    int diff = 0;
    if (opt_ptr)
    {
        diff = opt_len - old_len;

        if (*pkg_len + diff > MAX_FRAME_SIZE)
        {
            perror("Packet size exceeds MAX_FRAME_SIZE after option replacement!");
            return -1;
        }
        if (diff != 0)
        {
            uint8_t *next_opt_start = opt_ptr + 4 + old_len;
            size_t replaces_bytes = (options_start + options_len) - next_opt_start;
            memmove(opt_ptr + 4 + opt_len, next_opt_start, replaces_bytes);

            *(uint16_t *)(opt_ptr + 2) = htons(opt_len);

            *pkg_len += diff;

            pkg->payload.ip_udp_dhcp.ip.ip6_plen = htons(ntohs(pkg->payload.ip_udp_dhcp.ip.ip6_plen) + diff);
            pkg->payload.ip_udp_dhcp.udp.len = htons(ntohs(pkg->payload.ip_udp_dhcp.udp.len) + diff);
        }
        if (opt_len > 0 && opt_data != NULL)
        {
            memcpy(opt_ptr + 4, opt_data, opt_len);
        }

        return 0;
    }
    return -1;
}

uint16_t udp6_checksum(struct ip6_hdr *ip6, struct udphdr *udp, uint8_t *payload, size_t payload_len)
{
    uint32_t sum = 0;
    uint16_t *src = (uint16_t *)&ip6->ip6_src;
    uint16_t *dst = (uint16_t *)&ip6->ip6_dst;

    for (int i = 0; i < 8; i++)
    {
        sum += src[i];
        sum += dst[i];
    }

    sum += udp->len;
    sum += htons(ip6->ip6_nxt);
    
    sum += ntohs(udp->check);

    // Заголовок UDP
    sum += udp->source;
    sum += udp->dest;
    sum += udp->len;

    // Полезная нагрузка (DHCPv6)
    uint16_t *p = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++)
    {
        sum += p[i];
    }
    // Если нечетное количество байт
    if (payload_len % 2)
    {
        uint16_t last_word = 0;
        ((uint8_t *)&last_word)[0] = payload[payload_len - 1];
        sum += last_word;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t result = ~sum;
    return (result == 0) ? 0xFFFF : result;
}