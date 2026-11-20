/* ML-KEM-768 по FIPS 203 — для гибридной группы TLS X25519MLKEM768.
 *
 * Зачем: Chrome и другие современные клиенты предлагают в key_share
 * X25519MLKEM768 первым, и сервер выбирает его. Прямой контроль и испытание
 * обязаны вести полный TLS-обмен на форме клиента (ТЗ §4.3, §9, §11.1);
 * без ML-KEM рукопожатие на такой форме не завершить. Это грамматика
 * протокола (стандарт), не знание о коробке. */
#ifndef D2K_MLKEM_H
#define D2K_MLKEM_H

#include <stdint.h>

#define D2K_MLKEM768_EK 1184
#define D2K_MLKEM768_DK 2400
#define D2K_MLKEM768_CT 1088
#define D2K_MLKEM768_SS 32

/* KeyGen_internal(d, z) (FIPS 203, алг. 16): d и z — по 32 байта случайных. */
void d2k_mlkem768_keygen(const uint8_t d[32], const uint8_t z[32],
                         uint8_t ek[D2K_MLKEM768_EK], uint8_t dk[D2K_MLKEM768_DK]);
/* Encaps_internal(ek, m) (алг. 17). 0 — успех, -1 — ek не прошёл проверку модуля. */
int d2k_mlkem768_encaps(const uint8_t ek[D2K_MLKEM768_EK], const uint8_t m[32],
                        uint8_t ct[D2K_MLKEM768_CT], uint8_t ss[D2K_MLKEM768_SS]);
/* Decaps_internal(dk, c) (алг. 18) с неявным отказом: при подмене
 * шифртекста — псевдослучайный ключ J(z‖c), а не ошибка. */
void d2k_mlkem768_decaps(const uint8_t dk[D2K_MLKEM768_DK],
                         const uint8_t ct[D2K_MLKEM768_CT],
                         uint8_t ss[D2K_MLKEM768_SS]);

#endif
