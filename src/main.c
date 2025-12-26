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

//#include "gdhcp.h"

const int PORT=68;

static int replay_pcap_payloads_to_67(const char *pcap_path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *p = pcap_open_offline(pcap_path, errbuf);//pcap_t * — дескриптор для чтения пакетов (используется в pcap_loop, pcap_next и т.д.)
    if (!p) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return 1;
    }


    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        pcap_close(p);
        return 1;
    }

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    while (1) {
        int rc = pcap_next_ex(p, &hdr, &pkt);//читает следующий пакет из дескриптора, hdr- указатель на указатель заголовка pcap_pkthdr, pkt- данные
        if (rc == 0) continue;      // timeout (актуально для live, но пусть будет)
        if (rc == -2) break;        // EOF
        if (rc < 0) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(p));
            break;
        }

        if (hdr->caplen > 0) {
            printf("[DEBUG] Sending %u bytes\n", hdr->caplen);

            struct sockaddr_in dst = {0};
            dst.sin_family = AF_INET;
            dst.sin_port = htons(PORT);
            dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);

            ssize_t n = sendto(sock, pkt, hdr->caplen, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
            printf("[DEBUG] sendto returned: %zd\n", n);
        }

        // Небольшая пауза, чтобы connmand успевал обрабатывать
        usleep(20 * 1000);
    }

    close(sock);
    pcap_close(p);
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc<2){
        perror("Недостаточно аргументов в командной строке");
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
        char *args[] = {
                "/usr/sbin/connmand",
                "--debug",          // Запустить демоном
                "--noplugin=wifi",   // Отключить WiFi плагин
                NULL
        };
        execv("/usr/sbin/connmand", args);
        perror("execv failed");
        return 1;

    } else {
        //Родительский процесс
        printf("wrapper start with pid: %d\n", pid);
        usleep(20 * 1000);

        int r = replay_pcap_payloads_to_67(argv[1]);
        printf("replay_pcap returned: %d\n", r);
        sleep(10);
        // Чтобы wrapper не завершался мгновенно (и чтобы увидеть, не упал ли connmand)
        int st = 0;
        waitpid(pid, &st, 0);
        printf("connmand exited with status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    }

    return 0;
}