#include <net/ethernet.h>
#include "pcap.h"
#include "afl-fuzz.h"
#include "connman-1.32/gdhcp/common.h"
#include "utils.h"

#define PORT_SOURCE 67
#define PORT_DEST 68
#define PACKAGE_SIZE (sizeof(struct ether_header) + sizeof(struct ip_udp_dhcp_packet))

#define PCAP_FULL_SIZE (sizeof(struct pcap_file_header) + \
                        PACKAGE_SIZE)

typedef struct my_mutator
{
    afl_state_t *afl;
    unsigned int saved_seed;
    unsigned char *out_buf;
    size_t buf_size;
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
    mt->buf_size = 256 * 1024;
    mt->out_buf = malloc(mt->buf_size);

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
                       size_t max_size)
{
    my_mutator_t *mt = (my_mutator_t *)data;
    srand(mt->saved_seed ^ rand());

    FILE *log_file = fopen("/home/bobro/Desktop/diplom/src/mutatorv6_debug.log", "a"); // TODO заменить

    size_t pcap_file_hdr_size = sizeof(struct pcap_file_header);

    if (buf_size < pcap_file_hdr_size + sizeof(struct pcap_pkthdr))
    {
        fprintf(log_file, "buf_size(%zu) < min_required(%lu)\n",
                buf_size, pcap_file_hdr_size + sizeof(struct pcap_pkthdr) + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcpv6_packet, dhcpv6.options));
        fclose(log_file);

        *out_buf = buf;
        return buf_size;
    }

    size_t mut_size = buf_size > max_size ? max_size : buf_size;
    if (mut_size > mt->buf_size)
    {
        unsigned char *new_buf = realloc(mt->out_buf, mut_size);
        if (!new_buf)
        {
            *out_buf = buf;
            return buf_size;
        }
        mt->out_buf = new_buf;
        mt->buf_size = mut_size;
    }
    memcpy(mt->out_buf, buf, mut_size);

    size_t current_offset = pcap_file_hdr_size;
    int packet_count = 0;

    while (current_offset + sizeof(struct pcap_pkthdr) < mut_size)
    {
        struct pcap_pkthdr *pkt_hdr = (struct pcap_pkthdr *)(mt->out_buf + current_offset);
        size_t packet_data_offset = current_offset + sizeof(struct pcap_pkthdr);
        if (packet_data_offset + pkt_hdr->caplen > mut_size)
            break;

        struct ether_header *eth = (struct ether_header *)(mt->out_buf + packet_data_offset);
        if (ntohs(eth->ether_type) != 0x86DD)
            break;

        packet_count++;

        size_t option_offset = packet_data_offset + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcpv6_packet, dhcpv6.options);
        if (packet_data_offset + pkt_hdr->caplen >= option_offset)
        {
            struct ip_udp_dhcpv6_packet *packet = (struct ip_udp_dhcpv6_packet *)(mt->out_buf + packet_data_offset + sizeof(struct ether_header));
            packet->dhcpv6.message = rand() % 12;
            size_t options_len = (packet_data_offset + pkt_hdr->caplen) - option_offset;
            uint8_t *options = mt->out_buf + option_offset;

            fprintf(log_file, "packet№%d: options_len > 0, options_len = %zu\n",
                    packet_count, options_len);

            size_t i = 0;
            while (i + 4 < options_len)
            {
                uint16_t opt_type = ntohs(*(uint16_t *)(options + i));
                uint16_t opt_len = ntohs(*(uint16_t *)(options + i + 2));

                if (i + 4 + opt_len > options_len)
                    break;

                if (opt_len > 0)
                {
                    options[i + 4 + (rand() % opt_len)] ^= (1 << (rand() % 8));
                }
                i += 4 + opt_len;
            }
        }
        current_offset += sizeof(struct pcap_pkthdr) + pkt_hdr->caplen;
    }

    fclose(log_file);
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