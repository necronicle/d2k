/* d2k_ctl.h — управляющий сокет.
 *
 * Датапат слушает, контроллер подключается. Ровно одно подключение: датапат
 * обслуживает одного хозяина, а не является сервером общего пользования.
 *
 * Кадр: [длина payload u32 BE][тип u16 BE][payload]. Подробности и причины —
 * в docs/decisions/0004-control-socket.md.
 *
 * Событие — сообщение, а не обязательство. Не поместилось в сокет — потеряно
 * и посчитано. Очереди событий нет: очередь это память без предела, а §5.2
 * требует предела на всё. Пакетный путь ради контроллера не останавливается
 * никогда.
 *
 * AF_UNIX работает и на маке, поэтому модуль переносим и проверяется настоящим
 * сокетом, а не подделкой.
 */
#ifndef D2K_CTL_H
#define D2K_CTL_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_journal.h"

/* Предел кадра. План — самое большое, что здесь ездит. */
#define D2K_CTL_FRAME_MAX 65536

/* События: датапат → контроллер. */
#define D2K_EV_HELLO     0x0001  /* ключ + имя цели */
#define D2K_EV_SUSPECT   0x0002  /* ключ + код причины */
#define D2K_EV_APPLIED   0x0003  /* ключ + id плана */
#define D2K_EV_REFUSED   0x0004  /* ключ + код причины */
#define D2K_EV_EXCHANGE  0x0005  /* ключ + сколько байт пришло в ответ */
#define D2K_EV_STATS     0x0006  /* счётчики */

/* Команды: контроллер → датапат. */
#define D2K_CMD_SET_NAME 0x0081  /* длина имени u8, имя, план TLV */
#define D2K_CMD_SET_ADDR 0x0082  /* адрес u32 BE, план TLV */
#define D2K_CMD_DEL_NAME 0x0083  /* длина имени u8, имя */
#define D2K_CMD_DEL_ADDR 0x0084  /* адрес u32 BE */
#define D2K_CMD_CLEAR    0x0085  /* убрать все планы */
#define D2K_CMD_STATS    0x0086  /* прислать счётчики */

/* Коды причин подозрения живут в d2k_journal.h: они про наблюдение, а сокет
 * их только везёт. */

typedef struct d2k_ctl d2k_ctl;

/* Создаёт слушающий сокет по пути path. Существующий файл сокета убирается:
 * после SIGKILL он остаётся и мешает следующему запуску, а §5.5 требует
 * описанного пути восстановления. */
d2k_ctl *d2k_ctl_open(const char *path, char *err, size_t errcap);
void     d2k_ctl_close(d2k_ctl *c);

int d2k_ctl_listen_fd(const d2k_ctl *c);
int d2k_ctl_peer_fd(const d2k_ctl *c);   /* -1 — контроллер не подключён */

/* Принимает подключение, если оно ждёт. Второй контроллер отвергается. */
void d2k_ctl_accept(d2k_ctl *c);

/* Отправляет событие. Не блокирует. */
void d2k_ctl_event(d2k_ctl *c, uint16_t type, const uint8_t *body, size_t len);

/* Дописывает недоотправленный хвост, если он есть. */
void d2k_ctl_flush(d2k_ctl *c);

/* Читает и разбирает команды. cb зовётся на каждый целый кадр.
 * Возвращает число разобранных кадров; -1 — соединение закрылось. */
int d2k_ctl_poll(d2k_ctl *c,
                 void (*cb)(void *ctx, uint16_t type, const uint8_t *body, size_t len),
                 void *ctx);

uint64_t d2k_ctl_dropped(const d2k_ctl *c);
uint64_t d2k_ctl_sent(const d2k_ctl *c);

#endif /* D2K_CTL_H */
