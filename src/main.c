#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <linux/if_packet.h>
#include <net/if.h>

#include <systemd/sd-bus.h>

char *find_active_service_path(sd_bus *bus)
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

    attempts=0;
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

static int replay_pcap(const char *pcap_path)
{
    printf("start replay_pcap");
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *p = pcap_open_offline(pcap_path, errbuf); // pcap_t * — дескриптор для чтения пакетов (используется в pcap_loop, pcap_next и т.д.)
    if (!p)
    {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return 1;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("socket");
        pcap_close(p);
        return 1;
    }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex("veth-server"); // todo изменить
    device.sll_family = AF_PACKET;

    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    while (pcap_next_ex(p, &hdr, &pkt) == 1)
    {
        if (hdr->caplen > 0)
        {
            // 3. Отправляем пакет целиком (вместе с Ethernet заголовком)
            ssize_t n = sendto(sock, pkt, hdr->caplen, 0,
                               (struct sockaddr *)&device, sizeof(device));

            if (n < 0)
            {
                perror("sendto raw");
            }
            else
            {
                printf("[DEBUG] Raw packet sent: %zd bytes\n", n);
            }
        }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        usleep(10000);
#endif
    }

    close(sock);
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

    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return 1;
    }
    if (pid == 0)
    {
        // Дочерний процесс
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
        sd_bus *bus = NULL;
        int r = sd_bus_open_system(&bus);
        if (r < 0)
        {
            fprintf(stderr, "Не удалось открыть шину: %s\n", strerror(-r));
            return 1;
        }

        char *path = find_active_service_path(bus);
        printf("service_path: %s\n", path);
        // sleep(2);

        r = replay_pcap(argv[1]);
        printf("replay_pcap returned: %d\n", r);
        // #ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        sleep(1);
        // #endif

        kill(pid, SIGTERM);
        int st = 0;
        waitpid(pid, &st, 0);
        if (WIFSIGNALED(st))
        {
            raise(WTERMSIG(st));
        }
        printf("connmand exited with status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    }

    return 0;
}