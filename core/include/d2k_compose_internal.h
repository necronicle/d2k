/* d2k_compose_internal.h — сборщики TLV пяти зондов d2k_props_ask, открытые
 * НЕ ДЛЯ ВЫЗЫВАЮЩЕГО, А ДЛЯ ПРОВЕРКИ БАЙТ ЧЕРЕЗ planlab.
 *
 * Не часть контракта модуля (d2k_compose.h) — обычный код этим не
 * пользуется, и файл не описывает никакого инварианта снаружи compose.c.
 * Причина, зачем он всё-таки существует: обмен на настоящем ctlprobe
 * (test_compose.c) не зависит от СОДЕРЖИМОГО установленного плана — только
 * от того, ответил ли клиент "reply" на "hello" (ревью 11.09, круг правок 1
 * — мутации на бите порчи и на поле order молча проходили мимо такого
 * теста). datapath/planlab гоняет ТОТ ЖЕ исполнитель (d2k_plan_load +
 * d2k_plan_apply), что и прод, и показывает точные байты и порядок
 * посылок — единственный способ проверить содержимое без второй его
 * реализации в тесте (§2.5 запрещает вторую реализацию преобразований).
 * Отсюда эти четыре функции даны наружу под своими боевыми именами: тест,
 * который вызывает их и пишет результат на диск для planlab, гоняет РОВНО
 * то, что соберёт d2k_props_ask, а не копию, рискующую разойтись с ней.
 *
 * checksum/duplicates/parseProtocol у d2k_props_ask — одна и та же форма
 * (badsum_fake_plan_tlv) с разными payload/repeats/gap_us, поэтому здесь
 * одна функция на все три, не три. */
#ifndef D2K_COMPOSE_INTERNAL_H
#define D2K_COMPOSE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

int overlap_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);
int reorder_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);
int badsum_fake_plan_tlv(const uint8_t *payload, size_t paylen,
                         uint8_t repeats, uint32_t gap_us,
                         uint8_t *buf, size_t cap, size_t *out_len);
int checksum_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);

#endif /* D2K_COMPOSE_INTERNAL_H */
