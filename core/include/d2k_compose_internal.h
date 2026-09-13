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
 * одна функция на все три, не три.
 *
 * d2k_flowkey/ev_matches_flow добавлены ревью 11.09 (круг правок 2, находка
 * 1 — событие обмена не адресовано команде, см. большой комментарий у
 * wait_for_event в compose.c) по той же причине: test_compose.c проверяет
 * их РОВНО в том виде, в каком их читает d2k_props_ask, не копией. */
#ifndef D2K_COMPOSE_INTERNAL_H
#define D2K_COMPOSE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_compose.h" /* d2k_hello, d2k_props */
#include "d2k_link.h"    /* d2k_ev */

/* Удостоверяет собранный TLV: считает идентификатор по его байтам и вписывает
 * его на место записи REC_ID. Без него вопрос уходит на провод безымянным, и
 * событие «план применён» приписывается только по ключу потока. Подробности и
 * раскладка — у определения (compose.c). */
int plan_tlv_stamp_ident(uint8_t *tlv, size_t len, uint8_t out_id[D2K_PLAN_ID_LEN]);

int overlap_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);
int reorder_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);
int badsum_fake_plan_tlv(const uint8_t *payload, size_t paylen,
                         uint8_t repeats, uint32_t gap_us,
                         uint8_t *buf, size_t cap, size_t *out_len);
int checksum_plan_tlv(uint8_t *buf, size_t cap, size_t *out_len);

/* ТЕ ЖЕ четыре формы ТЕКСТОМ. Открыты той же причиной, что и их TLV-двойники
 * (см. шапку файла), плюс одной новой: перевод текста в байты провода
 * (core/plantlv.c) обязан давать РОВНО те байты, что собирает прямой
 * TLV-сборщик рядом. Сверить это можно только имея обе формы одной и той же
 * фигуры под рукой — иначе тест сверял бы перевод с собственным
 * представлением о нём. */
int overlap_plan_text(char *buf, size_t cap);
int reorder_plan_text(char *buf, size_t cap);
int badsum_fake_plan_text(const uint8_t *payload, size_t paylen,
                          unsigned repeats, uint32_t gap_us,
                          char *buf, size_t cap);
int checksum_plan_text(char *buf, size_t cap);

/* Ключ потока для фильтра wait_for_event — НЕУПОРЯДОЧЕННАЯ пара адрес:порт
 * плюс транспорт (не канонический d2k_key, datapath/include/d2k_track.h —
 * см. её большой комментарий в compose.c про то, почему вторая реализация
 * канонизации здесь не нужна и не заводится). */
typedef struct {
    uint8_t  a_ip[4], b_ip[4];
    uint16_t a_port, b_port;
    uint8_t  transport;
} d2k_flowkey;

int ev_matches_flow(const d2k_ev *ev, const d2k_flowkey *k);

/* Смысл одного вопроса, отдельно от того, кто его двигает: что послать и что
 * значит проход. Двигать вопросы умеют двое — блокирующая d2k_props_ask (для
 * d2kask) и планировщик d2kc, которому блокировать цикл нельзя. Две копии этой
 * развилки разошлись бы молча, и вектор свойств стал бы зависеть от того, кто
 * спрашивал. Подробности — в doc-комментариях в compose.c. */
int  d2k_props_question_plan(int q, d2k_hello control, size_t truth_len,
                             uint8_t *buf, size_t cap, size_t *out_len);
void d2k_props_question_passed(int q, d2k_props *pr);

/* ОДНО обращение к цели байтами h, НЕПОМЕЧЕННОЕ, с ОТКРЫТЫМ сокетом наружу.
 *
 * Открыто планировщику (core/sched.c) по той же причине, что и всё остальное
 * в этом файле: он задаёт те же пять вопросов, но двигает их своим циклом, и
 * второе обращение к цели, написанное рядом, разошлось бы с этим в мелочи,
 * которая стоила измерения. Обе оговорки — «непомеченный» и «сокет закрывает
 * вызывающий, ПОСЛЕ ожидания обмена» — не удобство, а условие того, что
 * измерение вообще что-то измеряет; см. doc-комментарий у самой функции. */
int  d2k_props_contact(const char *ip, uint16_t port, d2k_hello h,
                       uint8_t *local_ip4, uint16_t *local_port, int *out_fd);

/* ЗАНЯТЬ МЕСТНЫЙ ПОРТ ЗАРАНЕЕ, до всякого подключения.
 *
 * Нужно ровно для одного: испытание кандидата обязано действовать только на
 * поток зонда, а чтобы назвать этот поток датапату, его местный порт нужно
 * знать ДО того, как зонд пойдёт на цель (d2k_link_set_name_probe). После
 * connect знать поздно — план уже не поставить.
 *
 * Порт занимается настоящим bind, а не угадыванием свободного: угаданный
 * может оказаться занятым между выбором и подключением, и зонд ушёл бы с
 * другого порта, а план остался бы висеть на чужом.
 *
 * Сокет отдаётся ОТКРЫТЫМ и непомеченным: его дальше передают в
 * d2k_props_contact как готовый. Закрывает вызывающий. */
int  d2k_props_bind(int *out_fd, uint16_t *sport_be);

/* Как d2k_props_contact, но на УЖЕ ЗАНЯТОМ сокете (d2k_props_bind). use_fd
 * меньше нуля означает «создать свой» — тогда это в точности
 * d2k_props_contact. */
int  d2k_props_contact_on(int use_fd, const char *ip, uint16_t port, d2k_hello h,
                          uint8_t *local_ip4, uint16_t *local_port, int *out_fd);

#endif /* D2K_COMPOSE_INTERNAL_H */
