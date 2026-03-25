#include "utils.h"

void debug(const char *format, ...)
{
    printf("[DEBUG] ");

    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    printf("\n");
}

/**
 * @brief Читает PCAP файл и извлекает из него DHCP пакеты.
 * * Функция выделяет память под массив структур packet_t. Поддерживает IPv4 и IPv6.
 * * @param pcap_path Путь к файлу .pcap.
 * @param out_count Указатель, куда будет записано количество успешно прочитанных пакетов. Необходимо иницилизировать вне функции.
 * @return packet_t* Указатель на массив пакетов или NULL при ошибке. Требует free().
 */
packet_t *parse_pcap(const char *pcap_path, size_t *out_count)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    *out_count = 0;

    pcap_t *p = pcap_open_offline(pcap_path, errbuf);
    if (!p)
    {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return NULL;
    }

    packet_t *frames = calloc(MAX_PACKETS, sizeof(packet_t));

    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    while (pcap_next_ex(p, &hdr, &pkt) == 1 && *out_count < MAX_PACKETS)
    {
        if (hdr->caplen > 0)
        {
            struct ether_header *eth_hdr = (struct ether_header *)pkt;
            uint16_t ether_type = ntohs(eth_hdr->ether_type);
            packet_t *result = &frames[*out_count];

            if (ether_type == 0x0800)
            {
                result->type = PACKET_IPV4;
                size_t copy_size = (hdr->caplen < sizeof(frame_t)) ? hdr->caplen : sizeof(frame_t);
                memcpy(&result->pkt.v4, pkt, copy_size);
            }
            else if (ether_type == 0x86DD)
            {
                result->type = PACKET_IPV6;
                size_t copy_size = (hdr->caplen < sizeof(framev6_t)) ? hdr->caplen : sizeof(framev6_t);
                memcpy(&result->pkt.v6, pkt, copy_size);
            }

            (*out_count)++;
        }
    }
    pcap_close(p);
    return frames;
}

/**
 * @brief Основной цикл обработки и пересылки пакетов.
 * * Слушает сокет на наличие запросов от connman, подменяет идентификаторы (XID/MAC) 
 * в пакетах из PCAP и отправляет их обратно клиенту.
 * * @param sockfd Дескриптор RAW сокета.
 * @param sll Параметры адреса сетевого интерфейса (veth-server).
 * @param packages Массив заранее подготовленных пакетов из PCAP.
 * @param count_pkg Количество пакетов в массиве.
 */
void handler_packages(int sockfd, struct sockaddr_ll sll, packet_t *packages, size_t count_pkg)
{
    debug("handler packages");
    int size = 2048;
    char buf[size];
    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    int i = 0;
    while (i < count_pkg)
    {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 5)
            break;

        ssize_t n = recvfrom(sockfd, buf, size, 0, (struct sockaddr *)&src_addr, &addrlen); // TODO: возможно не всегда нужно будет получать пакет
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                debug("nothing received 1 second");
                continue;
            }
            perror("recvfrom");
            return;
        }

        struct ether_header *eth = (struct ether_header *)buf;
        uint16_t ether_type = ntohs(eth->ether_type);

        packet_t *current_pkg = &packages[i];

        if (ether_type == 0x0800 && current_pkg->type == PACKET_IPV4)
        {
            struct ip_udp_dhcp_packet *client_pkt = (struct ip_udp_dhcp_packet *)(buf + sizeof(struct ether_header));

            if (client_pkt->udp.uh_dport != htons(SERVER_PORT))
                continue;

            uint8_t *dhcp_message_type = dhcp_get_option(&client_pkt->data, DHCP_MESSAGE_TYPE);
            if (dhcp_message_type == NULL)
                continue;

            frame_t *pkg = &current_pkg->pkt.v4;

            // исправляем отправляемый пакет
            pkg->ip_udp_dhcp.data.xid = client_pkt->data.xid;
            memcpy(pkg->ip_udp_dhcp.data.chaddr, client_pkt->data.chaddr, 16);
            memcpy(pkg->eth_hdr.ether_shost, client_pkt->data.chaddr, 6);

            debug("received %s", dhcpv4_msg_to_str(*dhcp_message_type));

            n = sendto(sockfd, pkg, sizeof(frame_t), 0,
                       (struct sockaddr *)&sll, sizeof(sll));

            if (n < 0)
            {
                perror("sendto raw");
            }
            else
            {
                debug("Raw packet sent: %zd bytes", n);
            }
            ++i;
        }
        else if (ether_type == 0x86DD && current_pkg->type == PACKET_IPV6)
        {
            struct ip_udp_dhcpv6_packet *client_pkt = (struct ip_udp_dhcpv6_packet *)(buf + sizeof(struct ether_header));

            if (client_pkt->udp.uh_dport != htons(DHCPV6_SERVER_PORT))
                continue;

            uint8_t dhcp_message_type = client_pkt->dhcpv6.message;

            framev6_t *pkg = &current_pkg->pkt.v6;
            memcpy(pkg->ip_udp_dhcp.dhcpv6.transaction_id, client_pkt->dhcpv6.transaction_id, 3);
            memcpy(pkg->eth_hdr.ether_dhost, eth->ether_shost, 6);

            debug("received %s", dhcpv6_msg_to_str(dhcp_message_type));

            n = sendto(sockfd, pkg, sizeof(framev6_t), 0,
                       (struct sockaddr *)&sll, sizeof(sll));

            if (n < 0)
            {
                perror("sendto raw");
            }
            else
            {
                debug("Raw packet sent: %zd bytes", n);
            }
        }
        else
        {
            // debug("version client pkg != own version");
            continue;
        }
        ++i;
    }
}

/**
 * @brief Создает и настраивает виртуальную пару интерфейсов veth.
 * * Удаляет старые интерфейсы veth-client/veth-server и создает новые, 
 * переводя их в состояние UP.
 */
void setup_veth_interfaces()
{
    printf("[SETUP] Recreating veth interfaces...\n");

    // 1. Удаляем старые, если они остались (ошибка игнорируется, если их нет)
    system("ip link delete veth-client 2>/dev/null");

    // 2. Создаем пару заново
    if (system("ip link add veth-client type veth peer name veth-server") != 0)
    {
        fprintf(stderr, "Failed to create veth pair\n");
    }

    // 3. Поднимаем оба конца
    system("ip link set veth-client up");
    system("ip link set veth-server up");

    printf("[SETUP] Interfaces veth-client and veth-server are UP.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Ошибка: Недостаточно аргументов в командной строке.\n");
        fprintf(stderr, "Использование: %s <путь_к_pcap_файлу>\n", argv[0]);
        return 1;
    }
    printf("Program start!\n");

    system("killall -9 connmand 2>/dev/null");
    system("rm -rf /var/lib/connman/*");
    setup_veth_interfaces();

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex("veth-server");
    device.sll_family = AF_PACKET;

    bind(sock, (struct sockaddr *)&device, sizeof(device));

    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return 1;
    }
    if (pid == 0)
    {
        printf("Binary connmand start!\n");
        setenv("LLVM_PROFILE_FILE", "cov_data/connmand_%p.profraw", 1);
        char *bin = "/home/bobro/Desktop/diplom/src/connman-1.32/src/connmand";
        char *args[] = {
            bin,  // debug
            "-n", //--nodaemon
            "-c", "/etc/connman/main.conf",
            "-d", "gdhcp/dhcp.c,gdhcp/client.c,src/dhcp.c",
            NULL};
        execv(bin, args);
        perror("execv failed");
        _exit(1);
    }
    else
    {
        debug("wrapper start with pid: %d", pid);

        size_t count_pkg = 0;
        packet_t *fr = parse_pcap(argv[1], &count_pkg);
        if (!fr)
        {
            kill(pid, SIGABRT);
            int st = 0;
            waitpid(pid, &st, 0);
            exit(1);
        }

        handler_packages(sock, device, fr, count_pkg);

        free(fr);
        close(sock);

        kill(pid, SIGTERM);
        int st = 0;
        waitpid(pid, &st, 0);
        if (WIFSIGNALED(st))
        {
            raise(WTERMSIG(st));
        }
        else if (WIFEXITED(st))
        {
            int exit_code = WEXITSTATUS(st);
            printf("connmand exited with status: %d\n", exit_code);

            if (exit_code != 0)
            {
                printf("[!] Crash detected via non-zero exit code! Aborting wrapper...\n");
                raise(SIGTERM);
            }
        }
    }

    return 0;
}

void crashes_detect(char *filename)
{
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("socket");

        exit(1);
    }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex("veth-server");
    device.sll_family = AF_PACKET;

    bind(sock, (struct sockaddr *)&device, sizeof(device));

    size_t count = 0;
    packet_t *fr = parse_pcap(filename, &count);
    if (!fr)
    {
        exit(1);
    }

    handler_packages(sock, device, fr, count);

    free(fr);
    close(sock);
}