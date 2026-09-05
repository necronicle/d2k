/* d2k_time.h — единицы времени.
 *
 * Отдельным заголовком, потому что нужны и службе, и сессии, а дублирование
 * констант уже стоило ошибки: на aarch64 uint64_t это unsigned long, а литерал
 * с ull — unsigned long long, и printf ловил несовпадение ширины. UINT64_C
 * задаёт тип один раз и в одном месте.
 */
#ifndef D2K_TIME_H
#define D2K_TIME_H

#include <stdint.h>

#define NS_PER_S  UINT64_C(1000000000)
#define NS_PER_MS UINT64_C(1000000)
#define NS_PER_US UINT64_C(1000)

#endif /* D2K_TIME_H */
