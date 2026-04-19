#include "pcap.h"
#include "afl-fuzz.h"
#include "afl-mutations.h"

#include "utils.h"

#define PCAP_PKTHDR 16
#define LOGGING 0

typedef struct my_mutator
{
  afl_state_t *afl;
  unsigned int saved_seed;
  unsigned char *out_buf;
  unsigned char *mutate_buf;
  size_t buf_size;
  FILE *log_file;
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
  mt->mutate_buf = malloc(mt->buf_size);

  if (LOGGING)
  {
    mt->log_file = fopen("/home/bobro/Desktop/diplom/src/pcap_mutator.log", "w");
    if (!mt->log_file)
    {
      perror("[!] Custom Mutator: Failed to open log file");
    }
    else
    {
      fprintf(mt->log_file, "--- Mutator Initialized ---\n");
      fflush(mt->log_file);
    }
  }
  srand(seed);
  return mt;
}

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
  size_t pcap_file_hdr_size = sizeof(struct pcap_file_header);

  if (buf_size < pcap_file_hdr_size + PCAP_PKTHDR)
  {
    if (mt->log_file)
    {
      fprintf(mt->log_file, "[!] Skipped: buf_size (%zu) too small for valid PCAP\n", buf_size);
      fflush(mt->log_file);
    }
    *out_buf = buf;
    return buf_size;
  }

  if (max_size > mt->buf_size)
  {
    unsigned char *new_out = realloc(mt->out_buf, max_size);
    unsigned char *new_mut = realloc(mt->mutate_buf, max_size);

    if (!new_out || !new_mut)
    {
      *out_buf = buf;
      return buf_size;
    }

    mt->out_buf = new_out;
    mt->mutate_buf = new_mut;
    mt->buf_size = max_size;
  }

  size_t src_offset = pcap_file_hdr_size;
  size_t dst_offset = pcap_file_hdr_size;
  memcpy(mt->out_buf, buf, pcap_file_hdr_size);

  while (src_offset + PCAP_PKTHDR <= buf_size)
  {
    struct pcap_pkthdr *src_pcap_hdr = (struct pcap_pkthdr *)(buf + src_offset);
    size_t pcap_caplen = *(uint32_t *)(buf + src_offset + 8);

    if (src_offset + PCAP_PKTHDR + pcap_caplen > buf_size)
    {
      if (mt->log_file)
      {
        fprintf(mt->log_file, "[!] Break: packet truncated at offset %zu\n", src_offset);
        fflush(mt->log_file);
      }
      break;
    }

    struct ether_header *eth = (struct ether_header *)(buf + src_offset + PCAP_PKTHDR);
    uint16_t ether_type = ntohs(eth->ether_type);
    size_t dhcp_offset = 0;

    if (ether_type == 0x0800)
    {
      dhcp_offset = offsetof(frame_t, ip_udp_dhcp.data);
    }
    else if (ether_type == 0x86DD)
    {
      dhcp_offset = offsetof(framev6_t, payload.ip_udp_dhcp.dhcpv6);
    }

    if (dhcp_offset > 0 && pcap_caplen > dhcp_offset)
    {
      size_t payload_size = pcap_caplen - dhcp_offset;
      unsigned char *payload_data = (unsigned char *)eth + dhcp_offset;

      memcpy(mt->mutate_buf, payload_data, payload_size);

      u32 havoc_steps = 1 + rand_below(mt->afl, PCAP_PKTHDR);
      size_t new_payload_size = afl_mutate(mt->afl, mt->mutate_buf, payload_size, havoc_steps,
                                           false, true, add_buf, add_buf_size, max_size);

      size_t new_total_pkg_size = PCAP_PKTHDR + dhcp_offset + new_payload_size;
      if (dst_offset + new_total_pkg_size > max_size)
      {
        break;
      }

      struct pcap_pkthdr *dst_pcap_hdr = (struct pcap_pkthdr *)(mt->out_buf + dst_offset);
      memcpy(mt->out_buf + dst_offset, buf + src_offset, PCAP_PKTHDR);

      uint32_t new_caplen = (uint32_t)(dhcp_offset + new_payload_size);
      *(uint32_t *)(mt->out_buf + dst_offset + 8) = new_caplen;  // caplen
      *(uint32_t *)(mt->out_buf + dst_offset + 12) = new_caplen; // len

      memcpy(mt->out_buf + dst_offset + PCAP_PKTHDR, eth, dhcp_offset);

      memcpy(mt->out_buf + dst_offset + PCAP_PKTHDR + dhcp_offset, mt->mutate_buf, new_payload_size);

      int diff = (int)new_payload_size - (int)payload_size;
      if (ether_type == 0x0800)
      {
        frame_t *fr = (frame_t *)(mt->out_buf + dst_offset + PCAP_PKTHDR);
        uint16_t old_ip_len = ntohs(fr->ip_udp_dhcp.ip.tot_len);
        fr->ip_udp_dhcp.ip.tot_len = htons(old_ip_len + diff);

        fr->ip_udp_dhcp.ip.check = 0;
        fr->ip_udp_dhcp.ip.check = dhcp_checksum(&fr->ip_udp_dhcp.ip, fr->ip_udp_dhcp.ip.ihl * 4);

        uint16_t old_udp_len = ntohs(fr->ip_udp_dhcp.udp.len);
        fr->ip_udp_dhcp.udp.len = htons(old_udp_len + diff);
        fr->ip_udp_dhcp.udp.check = 0;
      }
      else if (ether_type == 0x86DD)
      {
        framev6_t *fr = (framev6_t *)(mt->out_buf + dst_offset + PCAP_PKTHDR);
        uint16_t old_ip6_plen = ntohs(fr->payload.ip_udp_dhcp.ip.ip6_plen);
        fr->payload.ip_udp_dhcp.ip.ip6_plen = htons(old_ip6_plen + diff);

        uint16_t old_udp_len = ntohs(fr->payload.ip_udp_dhcp.udp.len);
        fr->payload.ip_udp_dhcp.udp.len = htons(old_udp_len + diff);

        fr->payload.ip_udp_dhcp.udp.check = 0;
        size_t payload_len = ntohs(fr->payload.ip_udp_dhcp.udp.len) - sizeof(struct udphdr);
        fr->payload.ip_udp_dhcp.udp.check = udp6_checksum(&fr->payload.ip_udp_dhcp.ip, &fr->payload.ip_udp_dhcp.udp, &fr->payload.ip_udp_dhcp.dhcpv6, payload_len);
      }
      if (mt->log_file)
      {
        fprintf(mt->log_file, "Mutated %s: old_size=%zu, new_size=%zu, diff=%d\n",
                ether_type == 0x0800 ? "IPv4" : "IPv6", payload_size, new_payload_size, diff);
        fflush(mt->log_file);
      }

      dst_offset += new_total_pkg_size;
    }
    else
    {
      if (mt->log_file)
      {
        fprintf(mt->log_file, "[-] Skipped packet: ether_type=0x%04X, caplen=%u, dhcp_offset=%zu\n",
                ether_type, pcap_caplen, dhcp_offset);
        fflush(mt->log_file);
      }
      size_t total_pkg_size = PCAP_PKTHDR + pcap_caplen;
      if (dst_offset + total_pkg_size > max_size)
        break;

      memcpy(mt->out_buf + dst_offset, buf + src_offset, total_pkg_size);
      dst_offset += total_pkg_size;
    }

    src_offset += PCAP_PKTHDR + pcap_caplen;
  }

  *out_buf = mt->out_buf;
  return dst_offset;
}

void afl_custom_deinit(void *data)
{
  my_mutator_t *mt = (my_mutator_t *)data;
  if (mt->log_file)
  {
    fprintf(mt->log_file, "--- Mutator Deinitialized ---\n");
    fclose(mt->log_file);
  }
  free(mt->out_buf);
  free(mt->mutate_buf);
  free(mt);
}