#include <net/ethernet.h>
#include "pcap.h"
#include "afl-fuzz.h"
#include "connman-1.32/gdhcp/common.h"

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
* @brief Функция инициализации пользовательского мутатора, выполняемая один раз при запуске фаззера.
* Она позволяет подготовить внутренние структуры данных мутатора и настроить состояние генератора псевдослучайных чисел.
* Также отвечает за выделение памяти под рабочий буфер и открытие файла логирования.
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
        mt->log_file = fopen("/home/bobro/Desktop/diplom/src/mutatorv4_debug.log", "w");
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

/**
* @brief Ключевая функция мутации, заменяющая или дополняющая стандартную стадию havoc.
* В нее передается исходный тестовый сценарий, который модифицируется с опорой на заложенную логику парсинга.
* Алгоритм последовательно обрабатывает PCAPфайл-:
* - При обнаружении опции DHCP_MESSAGE_TYPE её значение принудительно заменяется на псевдослучайное число в диапазоне от 0 до 9.
* - Для прочих опций переменной длины применяется операция побитового исключающего ИЛИ (XOR) со случайно выбранным битом внутри диапазона Value.
* - Алгоритм реализует пересчет контрольной суммы заголовка IPv4 и намеренное обнуление контрольной суммы заголовка UDP.
* @param data Указатель на структуру состояния мутатора (my_mutator_t).
* @param buf Указатель на исходный буфер с данными входной( PCAP файл-).
* @param buf_size Размер исходного буфера в байтах.
* @param out_buf Указатель, куда будет записан адрес буфера с итоговыми мутированными данными.
* @param add_buf Указатель на буфер дополнительных данных словаря в( данном алгоритме не используется).
* @param add_buf_size Размер дополнительного буфера.
* @param max_size Максимально допустимый размер файла для AFL++.
* @return size_t Итоговый размер мутированных данных. Возвращает 0, если файл отбрасывается не( соответствует IPv4).
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
            fprintf(mt->log_file, "buf_size(%zu) < min_required\n", buf_size);
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
            fprintf(mt->log_file, "current_offset + 16 (%zu) < mut_size (%zu)\n",
                    current_offset + 16, mut_size);
            fflush(mt->log_file);
        }
        uint32_t caplen = *(uint32_t *)(mt->out_buf + current_offset + 8);
        size_t packet_data_offset = current_offset + PCAP_PKTHDR;
        if (packet_data_offset + caplen > mut_size)
            break;

        struct ether_header *eth = (struct ether_header *)(mt->out_buf + packet_data_offset);

        if (ntohs(eth->ether_type) != 0x0800)
        {
            if (mt->log_file)
            {
                fprintf(mt->log_file, "Packet not IPv4 (ether_type 0x%04X). Dropping file!\n", ntohs(eth->ether_type));
                fflush(mt->log_file);
            }
            *out_buf = NULL;
            return 0;
        }

        packet_count++;

        size_t option_offset = packet_data_offset + sizeof(struct ether_header) + offsetof(struct ip_udp_dhcp_packet, data.options);
        if (packet_data_offset + caplen >= option_offset)
        {
            struct ip_udp_dhcp_packet *packet = (struct ip_udp_dhcp_packet *)(mt->out_buf + packet_data_offset + sizeof(struct ether_header));
            size_t options_len = (packet_data_offset + caplen) - option_offset;
            uint8_t *options = mt->out_buf + option_offset;

            if (mt->log_file)
            {
                fprintf(mt->log_file, "packet№%d: options_len > 0, options_len = %zu\n",
                        packet_count, options_len);
                fflush(mt->log_file);
            }

            size_t i = 0;
            while (i + 2 < options_len)
            {
                uint8_t opt_type = options[i];
                if (opt_type == DHCP_END)
                    break;

                if (opt_type == 0)
                {
                    i++;
                    continue;
                }

                uint8_t opt_len = options[i + 1];

                if (i + 2 + opt_len > options_len)
                    break;

                uint8_t old_type, new_type;
                if (opt_type == DHCP_MESSAGE_TYPE && opt_len > 0)
                {
                    old_type = options[i + 2];
                    options[i + 2] = (uint8_t)(rand() % 10);
                    new_type = options[i + 2];

                    if (mt->log_file)
                    {
                        fprintf(mt->log_file, "[MUTATOR] packet№%d: Changed DHCP Message Type: %d -> %d (packet size: %zu)\n",
                                packet_count, old_type, new_type, mut_size);
                        fflush(mt->log_file);
                    }
                }
                else if (opt_len > 0)
                {
                    options[i + 2 + (rand() % opt_len)] ^= (1 << (rand() % 8));
                }
                i += 2 + opt_len;
            }
            packet->ip.check = 0;
            packet->ip.check = dhcp_checksum(&packet->ip, packet->ip.ihl * 4);
            packet->udp.check = 0;
        }
        current_offset += PCAP_PKTHDR + caplen;
    }

    *out_buf = mt->out_buf;
    return mut_size;
}

/**
* @brief Функция деинициализации пользовательского мутатора.
* Вызывается при завершении работы фаззера AFL++ для очистки ресурсов. Корректно закрывает дескрипторы файлов логирования и освобождает динамическую память, выделенную под структуру мутатора и рабочий буфер. 
* @param data Указатель на структуру состояния мутатора ( my_mutator_t), подлежащую удалению.
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