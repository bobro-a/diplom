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

#include <systemd/sd-bus.h>

#include "connman-1.32/gdhcp/common.h"
#include <sys/types.h>

char *wait_connmand(sd_bus *bus)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    char *found_path = NULL;

    int attempts = 0;
    while (attempts++ < 20)
    {

        int r = sd_bus_call_method(bus,
                                   "net.connman",         // Service
                                   "/",                   // Object Path
                                   "net.connman.Manager", // Interface
                                   "GetServices",         // Method
                                   &error,
                                   &reply,
                                   ""); // No input arguments

        if (r < 0)
        {
            sd_bus_error_free(&error);
            usleep(10000);
            continue;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(oa{sv})");
        if (r > 0)
        {
            const char *path;
            r = sd_bus_message_enter_container(reply, 'r', "oa{sv}"); // Входим в структуру
            if (r > 0)
            {
                sd_bus_message_read(reply, "o", &path); // Читаем путь
                found_path = strdup(path);
                sd_bus_message_exit_container(reply);
            }
            sd_bus_message_exit_container(reply);
        }

        sd_bus_message_unref(reply);

        if (found_path)
            break;
        usleep(10000);
    }

    attempts = 0;
    while (attempts++ < 20)
    {
        int r = sd_bus_call_method(bus,
                                   "net.connman",
                                   found_path,
                                   "net.connman.Service",
                                   "GetProperties",
                                   &error,
                                   &reply,
                                   "");
        if (r < 0)
        {
            fprintf(stderr, "[DBUS] GetProperties failed: %s\n", error.message);
            sd_bus_error_free(&error);
            free(found_path);
            return NULL;
        }

        int ready_to_exit = 0;
        if (sd_bus_message_enter_container(reply, 'a', "{sv}") > 0)
        {
            const char *key;
            while (sd_bus_message_enter_container(reply, 'e', "sv") > 0)
            {
                sd_bus_message_read(reply, "s", &key);

                if (strcmp(key, "State") == 0)
                {
                    const char *state;
                    sd_bus_message_read(reply, "v", "s", &state);
                    printf("[DBUS] Service State: %s\n", state);
                    if (strcmp(state, "configuration") == 0 ||
                        strcmp(state, "ready") == 0 ||
                        strcmp(state, "online") == 0)
                    {
                        ready_to_exit = 1;
                    }
                }
                else
                {
                    // Пропускаем остальные свойства
                    sd_bus_message_skip(reply, "v");
                }
                sd_bus_message_exit_container(reply);
            }
            sd_bus_message_exit_container(reply);
        }

        sd_bus_message_unref(reply);
        if (ready_to_exit)
            break;
        usleep(10000);
    }

    return found_path;
}

struct ip_udp_dhcp_packet *recv_discover(int sockfd, struct sockaddr_ll sll)
{
    int size = sizeof(struct ether_header) + sizeof(struct ip_udp_dhcp_packet);
    char buf[size];
    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);

    printf("[DEBUG] Waiting for DHCP Discover...\n");

    while (1)
    {
        ssize_t n = recvfrom(sockfd, buf, size, 0, (struct sockaddr *)&src_addr, &addrlen);
        if (n < 0)
        {
            perror("recvfrom");
            return NULL;
        }

        struct ip_udp_dhcp_packet *temp_pkt = (struct ip_udp_dhcp_packet *)(buf + sizeof(struct ether_header));

        if (temp_pkt->udp.uh_dport != htons(67))
            continue;

        uint8_t *options = temp_pkt->data.options;
        int is_discover = 0;
        for (int i = 0; i < DHCP_OPTIONS_BUFSIZE + EXTEND_FOR_BUGGY_SERVERS; i++)
        { // 308 — стандартный размер поля options
            if (options[i] == 53)
            { // Код опции DHCP Message Type
                if (options[i + 2] == DHCPDISCOVER)
                {
                    is_discover = 1;
                }
                break;
            }
            if (options[i] == DHCP_END)
                break;
        }
        if (is_discover)
        {
            struct ip_udp_dhcp_packet *result = malloc(sizeof(struct ip_udp_dhcp_packet));
            if (result)
            {
                memcpy(result, temp_pkt, sizeof(struct ip_udp_dhcp_packet));
                return result;
            }
            return NULL;
        }
    }
}

static int send_pcap(int sockfd, struct sockaddr_ll sll, const char *pcap_path, uint32_t client_xid, uint8_t client_chaddr[16])
{
    printf("start send_pcap\n");
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *p = pcap_open_offline(pcap_path, errbuf); // pcap_t * — дескриптор для чтения пакетов (используется в pcap_loop, pcap_next и т.д.)
    if (!p)
    {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    while (pcap_next_ex(p, &hdr, &pkt) == 1)
    {
        if (hdr->caplen > 0)
        {
            u_char mutable_pkt[hdr->caplen];
            memcpy(mutable_pkt, pkt, hdr->caplen);

            struct ip_udp_dhcp_packet *data = (struct ip_udp_dhcp_packet *)(mutable_pkt + sizeof(struct ether_header));
            data->data.xid = client_xid;
            memcpy(data->data.chaddr, client_chaddr, 16);

            struct ether_header *eth = (struct ether_header *)mutable_pkt;
            memcpy(eth->ether_shost, client_chaddr, 6);

            // 3. Отправляем пакет целиком (вместе с Ethernet заголовком)
            ssize_t n = sendto(sockfd, mutable_pkt, hdr->caplen, 0,
                               (struct sockaddr *)&sll, sizeof(sll));

            if (n < 0)
            {
                perror("sendto raw");
            }
            else
            {
                printf("[DEBUG] Raw packet sent: %zd bytes\n", n);
            }
        }
    }
    pcap_close(p);
    return 0;
}

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

    // bind(sock, (struct sockaddr *)&device, sizeof(device));

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
        // Родительский процесс
        printf("wrapper start with pid: %d\n", pid);

        // инициализируем шину, чтобы состояние connman узнать
        // sd_bus *bus = NULL;
        // int r = sd_bus_open_system(&bus);
        // if (r < 0)
        // {
        //     fprintf(stderr, "Не удалось открыть шину: %s\n", strerror(-r));
        //     return 1;
        // }

        // char *path = wait_connmand(bus);
        // printf("service_path: %s\n", path);

        struct ip_udp_dhcp_packet *packet = recv_discover(sock, device);
        if (packet == NULL)
            _exit(1);

        printf("\ndiscover packet received with xid %x!\n\n", packet->data.xid);
        int r = send_pcap(sock, device, argv[1], packet->data.xid,packet->data.chaddr);
        printf("replay_pcap returned: %d\n", r);
        sleep(1);

        kill(pid, SIGTERM);
        int st = 0;
        waitpid(pid, &st, 0);
        if (WIFSIGNALED(st))
        {
            raise(WTERMSIG(st));
        }
        printf("connmand exited with status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        close(sock);
    }

    return 0;
}