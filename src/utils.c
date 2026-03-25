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