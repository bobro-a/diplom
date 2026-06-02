#include "pcap.h"
#include "afl-fuzz.h"
#include "utils.h"

#define PCAP_PKTHDR 16
#define LOGGING 0

typedef struct my_mutator
{
    afl_state_t *afl;
    unsigned int saved_seed;
    unsigned char *out_buf;
    size_t buf_size;
    FILE *log_file;
} my_mutator_t;

/**
* @brief Функция инициализации пользовательского мутатора для фаззинга подсистемы IPv6.
* Выполняется один раз при запуске фаззера и позволяет подготовить внутренние структуры данных мутатора, а также настроить состояние генератора псевдослучайных чисел.
* Отвечает за выделение памяти под рабочий буфер и открытие файла логирования для отладки сессий мутации DHCPv6.
* @param afl Указатель на внутреннюю структуру состояния AFL++.
* @param seed Базовое значение для инициализации генератора псевдослучайных чисел.
* @return void* Указатель на инициализированную структуру состояния мутатора (my_mutator_t) или NULL при ошибке выделения памяти.
*/
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

    if (LOGGING)
    {
        mt->log_file = fopen("/home/bobro/Desktop/diplom/src/mutatorv6_debug.log", "w");
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

unsigned int afl_custom_fuzz_count(void *data, const unsigned char *buf, size_t buf_size);
void afl_custom_splice_optout(void *data);

/**
* @brief Ключевая функция направленной мутации для пакетов DHCPv6, заменяющая стадию havoc.
* Алгоритм выполняет строгую фильтрацию трафика на канальном уровне, пропуская исключительно кадры с маркером ether_type, равным 0x86DD (IPv6).
* В ходе модификации поле типа сообщения принудительно перезаписывается псевдослучайным значением в диапазоне от 0 до 11.
* Поскольку в DHCPv6 размер полей типа и длины увеличен до 16 бит, алгоритм синтаксического анализа осуществляет обход полезной нагрузки с фиксированным шагом в 4 байта.
* Точечные искажения (bit flipping) применяются исключительно к телу опции полю (Value).
* Ресурсоемкий пересчет контрольной суммы UDP в данном мутаторе опущен и делегирован утилитеоболочке- (Wrapper).
* @param data Указатель на структуру состояния мутатора.
* @param buf Указатель на исходный буфер с данными входной (PCAP-файл).
* @param buf_size Размер исходного буфера в байтах.
* @param out_buf Указатель, куда будет записан адрес буфера с итоговыми мутированными данными.
* @param add_buf Указатель на буфер дополнительных данных в (данном алгоритме не используется).
* @param add_buf_size Размер дополнительного буфера.
* @param max_size Максимально допустимый размер файла для инструмента AFL++.
* @return size_t Итоговый размер мутированных данных. Возвращает 0, если кадр отбрасывается не (является IPv6).
*/
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
            fprintf(mt->log_file, "buf_size(%zu) < min_required(%lu)\n",
                    buf_size, pcap_file_hdr_size + PCAP_PKTHDR + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcpv6_packet, dhcpv6.options));
            fflush(mt->log_file);
        }
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

    while (current_offset + PCAP_PKTHDR < mut_size)
    {
        if (mt->log_file)
        {
            fprintf(mt->log_file, "current_offset + sizeof(struct pcap_pkthdr) (%zu) < mut_size (%zu)\n",
                    current_offset + PCAP_PKTHDR, mut_size);
            fflush(mt->log_file);
        }
        struct pcap_pkthdr *pkt_hdr = (struct pcap_pkthdr *)(mt->out_buf + current_offset);
        size_t packet_data_offset = current_offset + PCAP_PKTHDR;
        uint32_t caplen = *(uint32_t *)(mt->out_buf + current_offset + 8);
        if (packet_data_offset + caplen > mut_size)
            break;

        struct ether_header *eth = (struct ether_header *)(mt->out_buf + packet_data_offset);
        if (ntohs(eth->ether_type) != 0x86DD)
        {
            if (mt->log_file)
            {
                fprintf(mt->log_file, "packet not dhcpv6 (offset: %zu, max: %zu)\n", current_offset + PCAP_PKTHDR, mut_size);
                fflush(mt->log_file);
            }
            *out_buf = NULL;
            return 0;
        }

        packet_count++;

        size_t option_offset = packet_data_offset + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcpv6_packet, dhcpv6.options);
        if (packet_data_offset + caplen >= option_offset)
        {
            struct ip_udp_dhcpv6_packet *packet = (struct ip_udp_dhcpv6_packet *)(mt->out_buf + packet_data_offset + sizeof(struct ether_header));
            packet->dhcpv6.message = rand() % 12;
            size_t options_len = (packet_data_offset + caplen) - option_offset;
            uint8_t *options = mt->out_buf + option_offset;

            if (mt->log_file)
            {
                fprintf(mt->log_file, "packet№%d: options_len > 0, options_len = %zu\n",
                        packet_count, options_len);
                fflush(mt->log_file);
            }
            size_t i = 0;
            while (i + 4 < options_len)
            {
                uint16_t opt_type, opt_len;
                memcpy(&opt_type, options + i, 2);
                opt_type = ntohs(opt_type);
                memcpy(&opt_len, options + i + 2, 2);
                opt_len = ntohs(opt_len);
                if (i + 4 + opt_len > options_len)
                    break;

                if (opt_len > 0)
                {
                    options[i + 4 + (rand() % opt_len)] ^= (1 << (rand() % 8));
                }
                i += 4 + opt_len;
            }
        }
        current_offset += PCAP_PKTHDR + caplen;
    }
    *out_buf = mt->out_buf;
    return mut_size;
}

/**
* @brief Функция деинициализации пользовательского мутатора.
* Вызывается при завершении работы фаззера для очистки ресурсов. Корректно закрывает дескриптор файла отладочного логированияи освобождает динамическую память, выделенную под структуру мутатора и рабочий выходной буфер.
* @param data Указатель на структуру состояния мутатора (my_mutator_t), подлежащую удалению.
* @return void
*/
void afl_custom_deinit(void *data)
{
    my_mutator_t *mt = (my_mutator_t *)data;
    if (mt->log_file)
    {
        fprintf(mt->log_file, "--- Mutator Deinitialized ---\n");
        fflush(mt->log_file);
        fclose(mt->log_file);
    }
    free(mt->out_buf);
    free(mt);
}