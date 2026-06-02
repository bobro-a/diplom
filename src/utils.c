#include "utils.h"

/**
* @brief Конвертация числового кода типа сообщения DHCPv4 встроковое представление.
* Используется для отладочного вывода и логирования состоянийконечного автомата протокола.
* @param type Числовой идентификатор типа сообщения (например, 1 для DHCPDISCOVER).
* @return const char* Строковое название типа сообщения или "UNKNOWN_DHCPV4".
*/
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

/**
* @brief Конвертация числового кода типа сообщения DHCPv6 в строковое представление.
* @param type Числовой идентификатор типа сообщения согласно (спецификации).
* @return const char* Строковое название типа сообщения или "UNKNOWN_DHCPV6".
*/
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

/**
* @brief Динамическая модификация замена() опции в пакете DHCPv6.
* Функция осуществляет поиск целевой опции в полезной нагрузке и заменяет её содержимое.
* Поскольку динамическая модификация приводит к изменению исходной длины пакета, алгоритм производит обязательный пересчет и обновление полей длин на уровнях IPv6 (ip6_plen) и UDP (len).
* @param pkg Указатель на структуру инкапсулированного кадра IPv6.
* @param pkg_len Указатель на текущую длину пакета будет(динамически обновлен при изменении размера).
* @param opt_code Код заменяемой опции (например, 1 для Client ID).
* @param opt_data Указатель на массив с новыми данными для вставки.
* @param opt_len Длина новых данных в байтах.
* @return int 0 в случае успешной замены, -1 при ошибке опция (не найдена или превышен MAX_FRAME_SIZE).
*/
int replace_dhcpv6_option(framev6_t *pkg, size_t *pkg_len, uint16_t opt_code, uint8_t *opt_data, uint16_t opt_len)
{
    uint8_t *options_start = (uint8_t *)pkg->payload.ip_udp_dhcp.dhcpv6.options;
    size_t options_len = *pkg_len - offsetof(framev6_t, payload.ip_udp_dhcp.dhcpv6.options);

    size_t offset = 0;
    uint8_t *opt_ptr = NULL;
    uint16_t old_len = 0;

    while (offset + 4 <= options_len)
    {
        uint16_t code = ntohs(*(uint16_t *)(options_start + offset));
        uint16_t len = ntohs(*(uint16_t *)(options_start + offset + 2));

        if (offset + 4 + len > options_len)
            break;

        if (code == opt_code)
        {
            opt_ptr = options_start + offset;
            old_len = len;
            break;
        }
        offset += 4 + len;
    }
    int diff = 0;
    if (opt_ptr)
    {
        diff = opt_len - old_len;

        if (*pkg_len + diff > MAX_FRAME_SIZE)
        {
            perror("Packet size exceeds MAX_FRAME_SIZE after option replacement!");
            return -1;
        }
        if (diff != 0)
        {
            uint8_t *next_opt_start = opt_ptr + 4 + old_len;
            size_t replaces_bytes = (options_start + options_len) - next_opt_start;
            memmove(opt_ptr + 4 + opt_len, next_opt_start, replaces_bytes);

            *(uint16_t *)(opt_ptr + 2) = htons(opt_len);

            *pkg_len += diff;

            pkg->payload.ip_udp_dhcp.ip.ip6_plen = htons(ntohs(pkg->payload.ip_udp_dhcp.ip.ip6_plen) + diff);
            pkg->payload.ip_udp_dhcp.udp.len = htons(ntohs(pkg->payload.ip_udp_dhcp.udp.len) + diff);
        }
        if (opt_len > 0 && opt_data != NULL)
        {
            memcpy(opt_ptr + 4, opt_data, opt_len);
        }

        return 0;
    }
    return -1;
}

/**
* @brief Вычисление контрольной суммы UDP для пакетов протокола IPv6.
* Алгоритм заново вычисляет контрольную сумму заголовка UDP с учетом псевдозаголовка IPv6 адресов (источника, назначения и длин).
* Реализованная логика побитового сложения и циклического переноса строго соответствует стандарту RFC 1071.
* @param ip6 Указатель на сетевой заголовок IPv6.
* @param udp Указатель на транспортный заголовок UDP.
* @param payload Указатель на начало прикладной полезной нагрузки (DHCPv6).
* @param payload_len Длина прикладной полезной нагрузки в байтах.
* @return uint16_t Вычисленная контрольная сумма пакета.
*/
uint16_t udp6_checksum(struct ip6_hdr *ip6, struct udphdr *udp, uint8_t *payload, size_t payload_len)
{
    uint32_t sum = 0;
    uint16_t *src = (uint16_t *)&ip6->ip6_src;
    uint16_t *dst = (uint16_t *)&ip6->ip6_dst;

    for (int i = 0; i < 8; i++)
    {
        sum += src[i];
        sum += dst[i];
    }

    sum += udp->len;
    sum += htons(ip6->ip6_nxt);
    
    sum += ntohs(udp->check);

    // Заголовок UDP
    sum += udp->source;
    sum += udp->dest;
    sum += udp->len;

    // Полезная нагрузка (DHCPv6)
    uint16_t *p = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++)
    {
        sum += p[i];
    }
    // Если нечетное количество байт
    if (payload_len % 2)
    {
        uint16_t last_word = 0;
        ((uint8_t *)&last_word)[0] = payload[payload_len - 1];
        sum += last_word;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t result = ~sum;
    return (result == 0) ? 0xFFFF : result;
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

    system("sysctl -w net.ipv6.conf.veth-client.accept_dad=0 2>/dev/null");
    system("sysctl -w net.ipv6.conf.veth-server.accept_dad=0 2>/dev/null");

    // 3. Поднимаем оба конца
    system("ip link set veth-client up");
    system("ip link set veth-server up");

    printf("[SETUP] Interfaces veth-client and veth-server are UP.\n");
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
            result->len = hdr->caplen;

            if (ether_type == 0x0800)
            {
                result->type = PACKET_IPV4;
                size_t copy_size = (hdr->caplen < MAX_FRAME_SIZE) ? hdr->caplen : MAX_FRAME_SIZE;
                memcpy(&result->pkt.v4, pkt, copy_size);
            }
            else if (ether_type == 0x86DD)
            {
                result->type = PACKET_IPV6;
                size_t copy_size = (hdr->caplen < MAX_FRAME_SIZE) ? hdr->caplen : MAX_FRAME_SIZE;
                memcpy(&result->pkt.v6, pkt, copy_size);
            }

            (*out_count)++;
        }
    }
    pcap_close(p);
    return frames;
}

/**
* @brief Форматированный вывод отладочной информации.
* Функция-оберткдля вывода диагностических сообщений Wrapper-утилиты в стандартный поток с префиксом [DEBUG].
* @param format Строка формата аналогично (printf).
* @param ... Переменное количество аргументов для форматирования.
* @return void
*/
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
* @brief Синхронное ожидание инициализации целевого демона connmand.
* Родительский процесс (Wrapper) через шину межпроцессного взаимодействия DBus отслеживает статус запущенного демона.
* Функция блокирует выполнение фаззера до тех пор, пока целевой сервис не перейдет в состояние готовности.
* @param bus Указатель на открытое соединение с системной шиной D-Bus.
* @return char* Указатель на динамически выделенную строку с D-Bus путем инициализированного сервиса требует (free), либо NULL в случае таймаута.
*/
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

/**
* @brief Активация режима DHCP-сервера через механизм Tethering. 
* Оболочка (Wrapper) отправляет структурированный запрос через D-Bus на включение режима Tethering для Ethernetтехнологии-.
* Данное воздействие принудительно переводит модуль автоматической конфигурации ConnMan из клиентского состояния в серверное.
* @param bus Указатель на открытое соединение с системной шиной D-Bus.
* @return int 0 в случае успешной активации режима, -1 при ошибке связи по D-Bus.
*/
int enable_ethernet_tethering(sd_bus *bus)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int r;
    r = sd_bus_call_method(bus,
                           "net.connman",                      // Destination (Service)
                           "/net/connman/technology/ethernet", // Object Path
                           "net.connman.Technology",           // Interface
                           "SetProperty",                      // Method
                           &error,
                           &reply,
                           "sv",                 // D-Bus Signature
                           "Tethering", "b", 1); // Arguments

    if (r < 0)
    {
        fprintf(stderr, "[-] Ошибка активации Tethering через D-Bus: %s\n", error.message);
        sd_bus_error_free(&error);
        return -1;
    }

    printf("[+] D-Bus команда на запуск DHCP-сервера (Tethering) успешно отправлена.\n");
    sd_bus_message_unref(reply);
    return 0;
}

/**
* @brief Синхронизация состояния ядра при создании сетевого интерфейса tether.
* Функция опрашивает ядро ОС, дожидаясь момента, когда виртуальный интерфейс-мост (tether), созданный демоном ConnMan, станет физически готов к передаче.
* Только после этого происходит открытие UDPпортов- для прослушивания входящих DHCPзапросов-.
* @return int 0 при успешной активации интерфейса, -1 в случае истечения таймаута ожидания.
*/
int wait_for_tether_interface()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("[-] Failed to create socket for ioctl");
        return -1;
    }

    struct ifreq ifr;
    int is_active = 0;
    int retries = 50; // 50 попыток по 100 мс = 5 секунд таймаута

    printf("[*] Waiting for 'tether' kernel interface to become UP and RUNNING...\n");

    while (retries > 0)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "tether", IFNAMSIZ - 1); // Имя моста, который создает ConnMan

        // Опрашиваем ядро о состоянии интерфейса
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            // Проверяем, что интерфейс административно включен (UP)
            // и физически готов к передаче (RUNNING)
            if ((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING))
            {
                is_active = 1;
                break;
            }
        }

        usleep(100000); // Спим 100 миллисекунд перед следующей проверкой
        retries--;
    }

    close(sock);

    if (is_active)
    {
        printf("[+] Interface 'tether' is fully operational!\n");
        return 0;
    }
    else
    {
        fprintf(stderr, "[-] Timeout waiting for 'tether' interface.\n");
        return -1;
    }
}