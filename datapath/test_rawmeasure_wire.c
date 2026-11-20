#include <stdio.h>
#include <string.h>
#include "d2k_rawmeasure_wire.h"
static int fails;
#define CHECK(x) do {if(!(x)){printf("FAIL line %d: %s\n",__LINE__,#x);fails++;}}while(0)
int main(void) {
 struct d2k_rawmeasure_request a={0},b;uint8_t wire[D2K_RM_REQUEST_LEN+1];
 a.tuple.family=4;a.tuple.proto=6;a.tuple.src[0]=1;a.tuple.dst[0]=2;
 a.tuple.sport_be[1]=9;a.tuple.dport_be[1]=8;a.epoch[0]=3;a.generation=0x0102030405060708ULL;a.token[15]=5;a.seconds=10;
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 CHECK(!d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));
 CHECK(!memcmp(&a.tuple,&b.tuple,sizeof a.tuple)&&b.generation==a.generation&&b.seconds==a.seconds);
 CHECK(!memcmp(a.epoch,b.epoch,16)&&!memcmp(a.token,b.token,16));
 CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN-1));
 CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN+1));
 wire[0]=5;CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));wire[0]=4;
 wire[1]=1;CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));wire[1]=6;
 wire[6]=1;CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));wire[6]=0;
 memset(wire+38,0,16);CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 memset(wire+54,0,8);CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 memset(wire+62,0,16);CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 wire[78]=0;CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));wire[78]=121;CHECK(d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));
 a.tuple.family=6;a.tuple.proto=17;a.tuple.src[15]=1;a.tuple.dst[15]=2;a.seconds=120;
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));CHECK(!d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN));CHECK(b.tuple.proto==17&&b.tuple.src[15]==1);
 a.renew=1;
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 CHECK(wire[78]==248&&!d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN)&&b.renew&&b.seconds==120);
 a.seconds=0;
 CHECK(!d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 CHECK(wire[78]==128&&!d2k_rawmeasure_request_read(&b,wire,D2K_RM_REQUEST_LEN)&&b.renew&&!b.seconds);
 a.renew=2;CHECK(d2k_rawmeasure_request_write(wire,D2K_RM_REQUEST_LEN,&a));
 a.renew=0;a.seconds=120;
 /* Reject contradictory evidence before it can reach strategy selection. */
#ifndef D2K_RM_REPORT_LEN
 CHECK(0); /* No result transport exists yet. */
#else
 struct d2k_rawmeasure_report r={0},decoded;
 uint8_t result[D2K_RM_REPORT_LEN+1];
 r.request=a;r.code=D2K_RM_REPEAT_SILENT;r.flags=D2K_RM_PRIOR_REPLY;
 r.sample_len=40;r.smallest_data=40;r.largest_data=40;
#ifdef D2K_RM_SAMPLE_DIGEST_LEN
 r.sample_digest[0]=0x12;r.sample_digest[31]=0x34;
#endif
 r.sample_seq=0x12345678;r.client_data=3;r.exact_repeats=2;
 CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 CHECK(!d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 CHECK(decoded.request.generation==a.generation && decoded.sample_seq==0x12345678 && decoded.exact_repeats==2);
#ifndef D2K_RM_SAMPLE_DIGEST_LEN
 CHECK(0); /* Missing content binding: equal lengths need not be equal data. */
#else
 CHECK(decoded.sample_digest[0]==0x12&&decoded.sample_digest[31]==0x34);
 memset(result+103,0,32);CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
#endif
 r.request.renew=1;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));r.request.renew=0;
 CHECK(result[87]==0x12&&result[88]==0x34&&result[89]==0x56&&result[90]==0x78);
 CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN-1));
 CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN+1));
 result[80]=0;CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN)); /* UDP one-way duplicates */
 result[80]=D2K_RM_PRIOR_REPLY|D2K_RM_CHANGED;
 CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 result[80]=128;CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 r.server_packets=1;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.code=D2K_RM_SERVER_PRESENT;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.server_packets=0;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.code=D2K_RM_REPEAT_SILENT;r.exact_repeats=3;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.exact_repeats=2;r.smallest_data=41;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.smallest_data=40;r.sample_len=2049;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.sample_len=40;r.code=D2K_RM_UNINFORMATIVE;r.server_packets=1;
 CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.server_packets=0;r.code=D2K_RM_UNMEASURED;r.flags=D2K_RM_OVERSIZED;
 CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r)); /* Cannot claim oversized with only 40-byte data. */
 r.largest_data=3000;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.flags=0;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.largest_data=40;r.flags=D2K_RM_PRIOR_REPLY;
 r.sample_len=40;r.code=D2K_RM_PENDING;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.code=255;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 /* Duplicate ACKs are retained as wire facts, not mistaken for delivered data. */
 r.request.tuple.proto=6;r.sample_seq=0xfffffff0u;r.sample_len=40;
 r.smallest_data=40;r.largest_data=40;r.client_data=3;r.exact_repeats=2;
 r.server_packets=1;r.flags=D2K_RM_TCP_ACK;r.tcp_ack=0xfffffff0u;
 r.code=D2K_RM_REPEAT_SILENT;
 CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 CHECK(!d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 CHECK(decoded.tcp_ack==r.tcp_ack && decoded.server_packets==1);
 r.tcp_ack=24;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.code=D2K_RM_SERVER_PRESENT;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.tcp_ack=23;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.code=D2K_RM_UNINFORMATIVE;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.flags=0;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.tcp_ack=0;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.flags=D2K_RM_TCP_ACK;r.request.tuple.proto=17;
 CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 /* v27 timing facts: explicit offsets, zero without an exact repeat. */
 CHECK(D2K_RM_REPORT_LEN==147u);
 r.request.tuple.proto=6;r.flags=0;r.server_packets=0;r.tcp_ack=0;r.code=D2K_RM_REPEAT_SILENT;
 r.repeat_gap_ms=64012u;r.repeat_age_ms=0x01020304u;
 CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 CHECK(result[139]==0&&result[140]==0&&result[141]==0xfa&&result[142]==0x0c);
 CHECK(result[143]==1&&result[144]==2&&result[145]==3&&result[146]==4);
 CHECK(!d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 CHECK(decoded.repeat_gap_ms==64012u&&decoded.repeat_age_ms==0x01020304u);
 r.exact_repeats=0;r.code=D2K_RM_UNINFORMATIVE;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.repeat_gap_ms=0;CHECK(d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 r.repeat_age_ms=0;CHECK(!d2k_rawmeasure_report_write(result,D2K_RM_REPORT_LEN,&r));
 result[142]=1;CHECK(d2k_rawmeasure_report_read(&decoded,result,D2K_RM_REPORT_LEN));
 CHECK(d2k_rm_ms(1999999u)==1u&&d2k_rm_ms(UINT64_MAX)==UINT32_MAX);

#endif
 puts(fails?"measurement wire FAILED":"measurement wire passed");return fails!=0;
}
