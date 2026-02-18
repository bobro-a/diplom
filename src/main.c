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


// const int PORT=68;

static int replay_pcap(const char *pcap_path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *p = pcap_open_offline(pcap_path, errbuf);//pcap_t * — дескриптор для чтения пакетов (используется в pcap_loop, pcap_next и т.д.)
    if (!p) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return 1;
    }


    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        pcap_close(p);
        return 1;
    }

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex("enp0s2"); 
    device.sll_family = AF_PACKET;

    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    while (pcap_next_ex(p, &hdr, &pkt) == 1) {
        if (hdr->caplen > 0) {
            // 3. Отправляем пакет целиком (вместе с Ethernet заголовком)
            ssize_t n = sendto(sock, pkt, hdr->caplen, 0,
                              (struct sockaddr *)&device, sizeof(device));
            
            if (n < 0) {
                perror("sendto raw");
            } else {
                printf("[DEBUG] Raw packet sent: %zd bytes\n", n);
            }
        }
        usleep(10 * 1000); // Небольшая пауза между пакетами
    }

    close(sock);
    pcap_close(p);
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc<2){
        fprintf(stderr, "Ошибка: Недостаточно аргументов в командной строке.\n");
        fprintf(stderr, "Использование: %s <путь_к_pcap_файлу>\n", argv[0]);
        return 1;
    }
    printf("Program start!\n");

    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        //Дочерний процесс
        printf("Binary connmand start!\n");
        setenv("LLVM_PROFILE_FILE", "cov_data/connmand_%p.profraw", 1);
        char* bin = "/usr/local/sbin/connmand";
        char *args[] = {
                bin,         // debug
                "-n",//--nodaemon
                "-d", "gdhcp/dhcp.c,gdhcp/client.c",
                NULL
        };
        execv(bin, args);
        perror("execv failed");
        _exit(1);

    } else {
        //Родительский процесс
        printf("wrapper start with pid: %d\n", pid);
        sleep(2);

        int r = replay_pcap(argv[1]);
        printf("replay_pcap returned: %d\n", r);
        sleep(5);

        kill(pid, SIGTERM);
        int st = 0;
        waitpid(pid, &st, 0);
        printf("connmand exited with status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    }

    return 0;
}