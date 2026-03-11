#include <net/ethernet.h>
#include "pcap.h"
#include "afl-fuzz.h"
#include "connman-1.32/gdhcp/common.h"

#define PORT_SOURCE 67
#define PORT_DEST 68
#define PACKAGE_SIZE (sizeof(struct ether_header) + sizeof(struct ip_udp_dhcp_packet))

#define PCAP_FULL_SIZE (sizeof(struct pcap_file_header) + \
                        PACKAGE_SIZE)

// static size_t mutation_dhcpv4_l2(uint8_t *buffer)
// {
//     // memset(buffer, 0, PACKAGE_SIZE); todo не затираем весь пакет
//     struct ether_header *eth = (struct ether_header *)buffer;
//     struct ip_udp_dhcp_packet *packet = (struct ip_udp_dhcp_packet *)(buffer + sizeof(struct ether_header));

//     memset(eth->ether_dhost, 0xFF, 6); // broadcast для offer
//     memset(eth->ether_shost, 0, 6);
//     eth->ether_type = htons(0x0800);

//     // заполняем dhcp
//     struct dhcp_packet *dhcp_pkt = &packet->data;

//     dhcp_pkt->flags |= htons(BROADCAST_FLAG);
//     dhcp_pkt->op = BOOTREPLY;
//     dhcp_pkt->htype = 1;
//     dhcp_pkt->hlen = 6;
//     dhcp_pkt->cookie = htonl(DHCP_MAGIC);
//     dhcp_pkt->options[0] = DHCP_END;

//     uint8_t type = DHCPOFFER;
//     type ^= (uint8_t)(1 << (rand() % 8));
//     dhcp_add_option_uint8(dhcp_pkt, DHCP_MESSAGE_TYPE, type);

//     memset(dhcp_pkt->chaddr, 0, 16);

//     enum
//     {
//         IP_UPD_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet) -
//                            EXTEND_FOR_BUGGY_SERVERS,
//         UPD_DHCP_SIZE = IP_UPD_DHCP_SIZE -
//                         offsetof(struct ip_udp_dhcp_packet, udp),
//     };

//     packet->ip.protocol = IPPROTO_UDP;
//     memset(&packet->ip.saddr, 0, 4); // заполняются во wrapper
//     memset(&packet->ip.daddr, 0, 4);
//     packet->udp.source = htons(PORT_SOURCE);
//     packet->udp.dest = htons(PORT_DEST);
//     /* size, excluding IP header: */
//     packet->udp.len = htons(UPD_DHCP_SIZE);
//     /* for UDP checksumming, ip.len is set to UDP packet len */
//     packet->ip.tot_len = packet->udp.len;
//     packet->udp.check = dhcp_checksum(packet, IP_UPD_DHCP_SIZE);
//     /* but for sending, it is set to IP packet len */
//     packet->ip.tot_len = htons(IP_UPD_DHCP_SIZE);
//     packet->ip.ihl = sizeof(packet->ip) >> 2;
//     packet->ip.version = IPVERSION;
//     packet->ip.ttl = IPDEFTTL;
//     packet->ip.check = dhcp_checksum(&packet->ip, sizeof(packet->ip));

//     return PACKAGE_SIZE;
// }

typedef struct my_mutator
{
    afl_state_t *afl;
    unsigned int saved_seed;
    unsigned char *out_buf;
} my_mutator_t;

void *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    my_mutator_t *mt = calloc(1, sizeof(*mt));
    if (!mt)
    {
        return NULL;
    }
    mt->afl = afl;
    mt->saved_seed = seed;
    mt->out_buf = malloc(PCAP_FULL_SIZE);
    srand(seed);
    return mt;
}

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size);
void afl_custom_splice_optout(void *data);

size_t afl_custom_fuzz(void *data,
                       unsigned char *buf,
                       size_t buf_size,
                       unsigned char **out_buf,
                       unsigned char *add_buf,
                       size_t add_buf_size,
                       size_t max_size) // зачем max_size
{
    my_mutator_t *mt = (my_mutator_t *)data;
    srand(mt->saved_seed ^ rand());

    FILE *log_file = fopen("/home/bobro/Desktop/diplom/src/mutator_debug.log", "a");

    size_t pcap_offset = sizeof(struct pcap_file_header) + 16;
    size_t dhcp_options_offset = pcap_offset + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcp_packet, data.options);
    size_t min_required = dhcp_options_offset;

    if (buf_size < min_required)
    {
        fprintf(log_file, "buf_size(%d) < min_required(%d)\n",
                buf_size, min_required);
        fclose(log_file);
        *out_buf = buf;
        return buf_size;
    }

    size_t mut_size = buf_size > max_size ? max_size : buf_size;
    memcpy(mt->out_buf, buf, mut_size);

    struct ip_udp_dhcp_packet *packet = (struct ip_udp_dhcp_packet *)(mt->out_buf + pcap_offset + sizeof(struct ether_header));

    size_t options_len = mut_size - dhcp_options_offset;

    if (options_len > 0)
    {
        fprintf(log_file, "options_len > 0, options_len = %d\n",
                options_len);

        uint8_t *options = mt->out_buf + dhcp_options_offset;
        size_t i = 0;
        while (i + 1 < options_len)
        {
            uint8_t opt_type = options[i];
            if (opt_type == DHCP_END)
                break;

            if (opt_type == DHCP_END)
            {
                break;
            }

            if (opt_type == 0)
            {
                i++;
                continue;
            }
            uint8_t opt_len = options[i + 1];
            uint8_t old_type, new_type;
            if (opt_type == DHCP_MESSAGE_TYPE)
            {
                if (i + 2 < options_len && opt_len > 0)
                {
                    old_type = options[i + 2];
                    options[i + 2] = (uint8_t)(rand() % 10);
                    new_type = options[i + 2];

                    fprintf(log_file, "[MUTATOR] Changed DHCP Message Type: %d -> %d (packet size: %zu)\n",
                            old_type, new_type, mut_size);
                }
                break;
            }
            i += 2 + opt_len;
        }
        // int target_byte = rand() % options_len;

        // mt->out_buf[dhcp_options_offset + target_byte] ^= (1 << (rand() % 8));
    }

    fclose(log_file);

    uint16_t ip_len = mut_size - pcap_offset - sizeof(struct ether_header);

    packet->ip.check = 0;
    packet->ip.check = dhcp_checksum(&packet->ip, packet->ip.ihl * 4);

    packet->udp.check = 0;
    // packet->udp.check = dhcp_checksum(packet, ip_len);

    *out_buf = mt->out_buf;
    return mut_size;
}

// const char *afl_custom_describe(void *data, size_t max_description_len);
// size_t afl_custom_post_process(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf);
// int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size);
// size_t afl_custom_trim(void *data, unsigned char **out_buf);
// int afl_custom_post_trim(void *data, unsigned char success);
// size_t afl_custom_havoc_mutation(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, size_t max_size);
// unsigned char afl_custom_havoc_mutation_probability(void *data);
// unsigned char afl_custom_queue_get(void *data, const unsigned char *filename);
// void (*afl_custom_fuzz_send)(void *data, const u8 *buf, size_t buf_size);
// u8 afl_custom_queue_new_entry(void *data, const unsigned char *filename_new_queue, const unsigned int *filename_orig_queue);
// const char *afl_custom_introspection(my_mutator_t *data);

void afl_custom_deinit(void *data)
{
    my_mutator_t *mt = (my_mutator_t *)data;
    free(mt->out_buf);
    free(mt);
}