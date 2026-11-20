#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include "server.c"
#include <assert.h>
int main(void) {
 FILE *fixture=tmpfile();assert(fixture);
 fputs("2026-11-20 18:25:01 d2k-tg-watchdog: probe failed: curl_rc=28 http=000 secret-string\n",fixture);
 fputs("2026-11-20 18:25:02 arbitrary secret-string\n",fixture);rewind(fixture);
 char output[4096]={0};panel_buf b={.p=output,.cap=sizeof output};
 diagnostic_tunnel_events(&b,fixture);fclose(fixture);
 assert(strstr(output,"18:25:01")&&strstr(output,"curl_rc=28")&&!strstr(output,"secret-string"));
 fixture=tmpfile();assert(fixture);fputs("2000 52 3 2 65535 4 5 100 1\n",fixture);rewind(fixture);
 b.len=0;diagnostic_queue(&b,fixture,2000);fclose(fixture);
 assert(strstr(output,"\"bound\":true")&&strstr(output,"\"userspace_drops\":5"));
 char dir[]="/tmp/d2k-diag-panel-XXXXXX";assert(mkdtemp(dir));
 d2k_panel_config c={.control_enabled=1,.diagnostics_dir=dir};
 int sv[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
 const char *good="POST / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\n\r\n";
 assert(api_diagnostics(sv[0],&c,good,"POST","enable")==0);
 char buf[2048];ssize_t n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"200 OK"));assert(d2k_diag_enabled(dir));
 assert(api_diagnostics(sv[0],&c,"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n","POST","disable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"403"));assert(d2k_diag_enabled(dir));
 assert(api_diagnostics(sv[0],&c,good,"POST","disable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);assert(!d2k_diag_enabled(dir));
 close(sv[0]);close(sv[1]);rmdir(dir);puts("diagnostic panel controls PASS");
}
