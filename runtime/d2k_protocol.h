#ifndef D2K_PROTOCOL_H
#define D2K_PROTOCOL_H
/* One source for the control handshake, release CLI and health records. */
/* v24 (этапы 12/16/17, аудит 21): форма RAW (8) в SET_ADDR/DEL_ADDR/SET_NAME_PROBE/
 * DEL_NAME_PROBE и в контексте привязки APPLIED/EXCHANGE/SUSPECT. Старый датапат
 * (v23) отвергал бы SET_ADDR формы 8 кодом BAD_ARGS, старый контроллер терял бы
 * события с контекстом RAW как «повреждённый контекст»: пара обязана обновляться
 * вместе, и приветствие это обеспечивает точным совпадением версии. */
/* v25: raw measurement requests/results and immutable flow incarnations on
 * raw suspicions. Both peers must understand the measurement lifecycle. */
/* v26: RAW reports retain cumulative TCP ACK evidence; packet presence
 * alone cannot terminate a stalled-data observation. */
/* v27: RAW reports carry the measured monotonic interval between the last two
 * exact client copies and its age; the trial window is derived from them. */
/* v28: RAW renew-only/cancel bit; TCP acquisition and comparison phases
 * preserve the same evidence under controller heartbeats. */
/* v29: direct TLS EXCHANGE retains its actual flow identity for passive controls. */
/* v30: permanent service installation echoes its request token and binding. */
/* v31: preflight START/HANDOVER/GAVE_UP carry tuple, K, elapsed and immutable
 * plan/trial/binding context. Both peers must preserve these new facts. */
/* v32: staged preflight endpoint candidates; token-conditional cleanup and promotion. */
/* v34: scoped, expiring preflight leases are authorized by client/DNS context. */
#define D2K_CTL_PROTO_VERSION 34u
#endif
