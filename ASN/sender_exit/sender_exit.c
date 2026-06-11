#include "common/net.h"
#include "common/packet.h"
#include "common/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
static void log_err(const char *m){fprintf(stderr,"[SndExt] ERROR: %s\n",m);fflush(stderr);}
typedef struct{SOCKET s;}conn_ctx_t;
static DWORD WINAPI handle_connection(LPVOID arg){
    conn_ctx_t *ctx=(conn_ctx_t*)arg;
    SOCKET sock=ctx->s; free(ctx);
    uint8_t mode=0;
    if(net_recv_all(sock,&mode,1)!=0){goto done;}
    if(mode==MODE_RESPONSE){
        uint8_t pb[2];
        if(net_recv_all(sock,pb,2)!=0){log_err("read port");goto done;}
        uint16_t sport=(uint16_t)((pb[0]<<8)|pb[1]);
        wire_packet_t pkt={0};
        if(net_recv_all(sock,pkt.data,WIRE_PACKET_SIZE)!=0){log_err("read pkt");goto done;}
        SOCKET s=net_connect(LOCALHOST,sport);
        if(s==INVALID_SOCKET){log_err("connect sender");goto done;}
        net_send_all(s,pkt.data,WIRE_PACKET_SIZE);net_close(s);
    }
done: net_close(sock);return 0;
}
int main(void){
    SetConsoleOutputCP(65001);
    if(net_init()!=0)return 1;
    SOCKET srv=net_listen(PORT_SENDER_EXIT);
    if(srv==INVALID_SOCKET){net_cleanup();return 1;}
    printf("[SndExt] ready\n");fflush(stdout);
    while(1){
        SOCKET cs=net_accept(srv);if(cs==INVALID_SOCKET)continue;
        conn_ctx_t *ctx=malloc(sizeof(conn_ctx_t));if(!ctx){net_close(cs);continue;}
        ctx->s=cs;
        HANDLE t=CreateThread(NULL,0,handle_connection,ctx,0,NULL);
        if(!t){net_close(cs);free(ctx);continue;}CloseHandle(t);
    }
    net_close(srv);net_cleanup();return 0;
}
