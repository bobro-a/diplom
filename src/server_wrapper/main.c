#include "../utils.h"

#ifndef __AFL_COMPILER
#define __AFL_LOOP(x) ({ static int macro_i = 1; int macro_r = macro_i; macro_i = 0; macro_r; })
#endif


char __start___debug[1] = {0};
extern char __stop___debug[1] __attribute__((alias("__start___debug")));

void generate_client_mac(uint8_t *mac_buffer)
{
    for (int i = 0; i < 6; i++)
    {
        mac_buffer[i] = rand() % 256;
    }

    mac_buffer[0] &= 0xFE;

    mac_buffer[0] |= 0x02;
}

uint32_t generate_xid_v4()
{
    // Комбинируем два вызова rand(), чтобы надежно покрыть 32 бита
    uint32_t xid = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    return xid;
}

void generate_transaction_id(uint8_t *tid_buffer)
{
    tid_buffer[0] = rand() % 256;
    tid_buffer[1] = rand() % 256;
    tid_buffer[2] = rand() % 256;
}

void generate_duid(uint8_t *mac, uint8_t *duid_payload)
{
    memset(duid_payload, 0, 10);

    // DUID Type: 3 (DUID-LL - Link-Layer Address)
    duid_payload[0] = 0x00;
    duid_payload[1] = 0x03;

    // Hardware Type: 1 (Ethernet)
    duid_payload[2] = 0x00;
    duid_payload[3] = 0x01;

    // Копируем наши 6 байт сгенерированного LAA MAC-адреса
    memcpy(&duid_payload[4], mac, 6);
}
/**
* @brief Осуществляет маршрутизацию и модификацию мутированных пакетов.
* Функция отправляет пакеты IPv4 целевому демону, динамически заменяя опции
* пересчитывает контрольные суммы и ожидает ответ.
* @param sockfd Файловый дескриптор RAW-сокета.
* @param sll Структура адреса канального уровня (sockaddr_ll).
* @param packages Указатель на массив пакетов, извлеченных из PCAP.
* @param count_pkg Количество пакетов в массиве.
* @return void
*/
void handler_packages(int sockfd, struct sockaddr_ll sll, packet_t *packages, size_t count_pkg)
{
    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    packet_t *temp_pkg;
    uint8_t mac[16] = {0};
    uint32_t xid = generate_xid_v4();
    uint8_t transaction_id[3];

    generate_transaction_id(transaction_id);
    generate_client_mac(mac);

    uint8_t client_id[10] = {0};
    generate_duid(mac, client_id);

    uint32_t server_ip = 0;
    uint32_t offered_ip = 0;
    int repeats = 3;
    int expected_reply = 0; // 0 - ждем DHCP, 1 - ждем RA
    for (int i = 0; i < count_pkg;)
    {
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (now.tv_sec - start.tv_sec > 5)
            break;

        temp_pkg = &packages[i];
        char *pkg;

        if (temp_pkg->type == PACKET_IPV4)
        {
            struct ip_udp_dhcp_packet *packet = &temp_pkg->pkt.v4.ip_udp_dhcp;

            memcpy(&packet->data.chaddr, mac, 16);
            packet->data.xid = xid;

            struct ether_header *eth = (struct ether_header *)&temp_pkg->pkt.v4;
            memcpy(eth->ether_shost, mac, 6);

            if (server_ip != 0 && offered_ip != 0)
            {
                uint8_t *opts = packet->data.options;
                int opt_idx = 0;
                uint8_t msg_type = 0;

                while (opt_idx < DHCP_OPTIONS_BUFSIZE)
                {
                    uint8_t opt_type = opts[opt_idx];
                    if (opt_type == 255)
                        break; // End Option
                    if (opt_type == 0)
                    {
                        opt_idx++;
                        continue;
                    } // Pad Option

                    uint8_t opt_len = opts[opt_idx + 1];

                    if (opt_type == 53 && opt_len == 1)
                    {
                        msg_type = opts[opt_idx + 2];
                    }

                    // Заменяем Опцию 54 (Server Identifier)
                    if (opt_type == 54 && opt_len == 4)
                    {
                        memcpy(&opts[opt_idx + 2], &server_ip, 4);
                        printf("[*] Injected Server IP into Option 54\n");
                    }
                    // Заменяем Опцию 50 (Requested IP Address)
                    if (opt_type == 50 && opt_len == 4)
                    {
                        memcpy(&opts[opt_idx + 2], &offered_ip, 4);
                        printf("[*] Injected Offered IP into Option 50\n");
                    }
                    opt_idx += 2 + opt_len; // Прыгаем к следующей опции
                }
                if (msg_type == 7 || msg_type == 8)
                {
                    packet->data.ciaddr = offered_ip;

                    packet->ip.saddr = offered_ip;
                    packet->ip.daddr = server_ip;

                    printf("[*] Patched ciaddr and IP header for RELEASE/INFORM\n");
                }
            }

            packet->ip.check = 0;
            packet->ip.check = dhcp_checksum(&packet->ip, packet->ip.ihl * 4);
            packet->udp.check = 0;
            pkg = (char *)&temp_pkg->pkt.v4;
        }
        else if (temp_pkg->type == PACKET_IPV6)
        {
            struct ip6_hdr *send_ipv6 = (struct ip6_hdr *)((uint8_t *)&temp_pkg->pkt.v6 + sizeof(struct ether_header));
            if (send_ipv6->ip6_nxt == IPPROTO_ICMPV6)
            {
                pkg = (char *)&temp_pkg->pkt.v6;
                expected_reply = 1;
                debug("[IPv6] Sending ICMPv6 (RS), waiting for RA...");
            }
            else if (send_ipv6->ip6_nxt == IPPROTO_UDP)
            {
                struct ether_header *eth_v6 = (struct ether_header *)&temp_pkg->pkt.v6;
                memcpy(eth_v6->ether_shost, mac, 6);

                int res = replace_dhcpv6_option(&temp_pkg->pkt.v6, &temp_pkg->len, 1, client_id, 10);

                if (res == 0)
                {
                    debug("Client ID successfully replaced in outgoing packet.");
                }
                else
                {
                    debug("Failed to replace Client ID (Option not found in template or size error).");
                }
                struct ip_udp_dhcpv6_packet *payload = &temp_pkg->pkt.v6.payload.ip_udp_dhcp;
                memcpy(&payload->dhcpv6.transaction_id, transaction_id, 3);

                uint8_t dhcp_message_type = payload->dhcpv6.message;
                struct udphdr *udp = &payload->udp;
                uint8_t *dhcp = (uint8_t *)&payload->dhcpv6;

                uint16_t payload_len = temp_pkg->len - sizeof(struct ether_header) - sizeof(struct ip6_hdr);
                send_ipv6->ip6_plen = htons(payload_len); // Обновляем длину в IPv6
                udp->len = htons(payload_len);
                size_t dhcp_len = ntohs(udp->len) - sizeof(struct udphdr);

                udp->check = 0;
                udp->check = udp6_checksum(send_ipv6, udp, dhcp, dhcp_len);

                debug("received %s", dhcpv6_msg_to_str(dhcp_message_type));

                pkg = (char *)&temp_pkg->pkt.v6;
                expected_reply = 0;
                debug("[IPv6] Sending DHCPv6, waiting for response...");
            }
        }

        ssize_t n = sendto(sockfd, pkg, temp_pkg->len, 0,
                           (struct sockaddr *)&sll, sizeof(sll));
        repeats--;

        if (n < 0)
            perror("sendto raw");
        else
            debug("Raw packet sent: %zd bytes", n);

        int is_recv = 0;
        struct timespec start_resend;
        clock_gettime(CLOCK_MONOTONIC, &start_resend);
        while (!is_recv)
        {
            clock_gettime(CLOCK_MONOTONIC, &now);

            if (now.tv_sec - start_resend.tv_sec > 1)
                break;

            char buf[2048];
            int size = sizeof(buf);
            n = recvfrom(sockfd, buf, size, 0, (struct sockaddr *)&src_addr, &addrlen);
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

            if (temp_pkg->type == PACKET_IPV4 && ether_type == 0x0800)
            {
                frame_t *recv_pkg = (frame_t *)buf;
                struct ip_udp_dhcp_packet *payload = &recv_pkg->ip_udp_dhcp;

                if (payload->ip.protocol != IPPROTO_UDP)
                    continue;

                uint16_t src_port = ntohs(payload->udp.source);
                uint16_t dst_port = ntohs(payload->udp.dest);
                uint32_t recv_xid = payload->data.xid;
                uint8_t *dhcp_message_type = dhcp_get_option(&payload->data, DHCP_MESSAGE_TYPE);
                if (dhcp_message_type == NULL)
                    continue;

                if (dst_port != CLIENT_PORT)
                {
                    continue;
                }

                if (recv_xid != xid)
                {
                    printf("[-] XID mismatch! Ignoring packet.\n");
                    continue;
                }

                debug("Received message: %s src=%u, dst=%u, recv_xid=0x%08X (our_xid=0x%08X)\n",
                      dhcpv4_msg_to_str(*dhcp_message_type), src_port, dst_port, recv_xid, xid);
                server_ip = payload->ip.saddr;
                offered_ip = payload->data.yiaddr;

                is_recv = 1;
            }
            else if (temp_pkg->type == PACKET_IPV6 && ether_type == 0x86DD)
            {
                struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(buf + sizeof(struct ether_header));
                if (ipv6_hdr->ip6_nxt == IPPROTO_ICMPV6)
                {
                    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(buf + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

                    if (expected_reply == 1)
                    {
                        debug("[+] Expected RA received!");
                        is_recv = 1;
                        continue;
                    }
                    else
                    {
                        continue;
                    }
                    continue;
                }

                if (ipv6_hdr->ip6_nxt != IPPROTO_UDP || expected_reply == 1)
                    continue;

                framev6_t *recv_pkg = (framev6_t *)buf;
                struct ip_udp_dhcpv6_packet *payload = &recv_pkg->payload.ip_udp_dhcp;

                if (ntohs(payload->udp.dest) != DHCPV6_CLIENT_PORT || memcmp(payload->dhcpv6.transaction_id, transaction_id, 3) != 0)
                    continue;

                uint16_t opt_len = 0;
                uint8_t *option = dhcpv6_get_option(&payload->dhcpv6, sizeof(payload->dhcpv6), 1, &opt_len,
                                                    NULL);

                if (option == NULL || opt_len != 10 || memcmp(option, client_id, 10) != 0)
                    continue;

                is_recv = 1;
            }
            else
                continue;
        }

        if (!repeats && !is_recv)
        {
            debug("finishing the iteration, the server is not responding");
            return;
        }
        if (is_recv)
        {
            ++i;
            is_recv = 0;
            repeats = 3;
        }
    }
}

/**
* @brief Главная точка входа Wrapper-оболочки режим(тестирования DHCP-сервера).
* Функция инициализирует среду, запускает демон connmand через fork/exec,
* настраивает D-Bus соединение (Tethering) и управляет циклом фаззинга AFL++.
* @param argc Количество аргументов командной строки.
* @param argv Массив аргументов. Ожидается [1] - путь к файлу. pcap.
* @return int 0 при успешном завершении, 1 при ошибке инициализации.
*/
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
    system("ip link delete tether 2>/dev/null");
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
        setenv("ASAN_OPTIONS", "handle_segv=1:allow_user_segv_handler=0:abort_on_error=1:detect_leaks=0", 1);
        setenv("AFL_NO_FORKSRV", "1", 1);

        char *bin = "/home/bobro/Desktop/diplom/src/connman-1.32/src/connmand";
        char *args[] = {
            bin,  // debug
            "-n", //--nodaemon
            "-r",
            "-c", "/etc/connman/main.conf",
            "-d", "gdhcp/dhcp.c,gdhcp/server.c,src/dhcp.c",
            NULL};
        execv(bin, args);
        perror("execv failed");
        _exit(1);
    }
    else
    {
        debug("wrapper start with pid: %d", pid);
        // wait connmad initialization
        sd_bus *bus = NULL;
        int r = sd_bus_open_system(&bus);
        if (r < 0)
        {
            fprintf(stderr, "Не удалось открыть шину: %s\n", strerror(-r));
            return 1;
        }

        char *path = wait_connmand(bus);
        printf("connmand initialization for service_path: %s\n", path);
        free(path);

        int res = enable_ethernet_tethering(bus);
        if (res < 0)
        {
            kill(pid, SIGABRT);
            int st = 0;
            waitpid(pid, &st, 0);
            exit(1);
        }

        res = wait_for_tether_interface();
        if (res < 0)
        {
            kill(pid, SIGABRT);
            int st = 0;
            waitpid(pid, &st, 0);
            exit(1);
        }

        while (__AFL_LOOP(10000))
        {
            int st;

            if (waitpid(pid, &st, WNOHANG) > 0)
            {
                printf("[!] Target process (connmand) crashed during fuzzing!\n");

                if (WIFSIGNALED(st))
                {
                    raise(WTERMSIG(st));
                }
                else
                {
                    abort();
                }
            }
            size_t count_pkg = 0;
            packet_t *fr = parse_pcap(argv[1], &count_pkg);
            if (!fr)
            {
                continue;
            }

            handler_packages(sock, device, fr, count_pkg);
            free(fr);
        }

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
