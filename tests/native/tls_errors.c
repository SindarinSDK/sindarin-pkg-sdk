/* The same calls exercise original generated C storage and canonical storage. */
#ifdef TLS_LEGACY_HEADER
#include TLS_LEGACY_HEADER
#else
#include "tls.native.h"
#endif
#include <string.h>

int main(int argc,char **argv)
{
    if(argc<2)return 2;
    if(!strcmp(argv[1],"null-connect"))sn_tls_stream_connect(NULL);
    else if(!strcmp(argv[1],"invalid-connect"))sn_tls_stream_connect("[invalid");
    else if(!strcmp(argv[1],"null-bind"))sn_tls_listener_bind(NULL,NULL,NULL);
    else if(!strcmp(argv[1],"invalid-bind"))sn_tls_listener_bind("[invalid","unused","unused");
    else if(!strcmp(argv[1],"missing-certificate"))sn_tls_listener_bind("127.0.0.1:0","missing.pem","missing.key");
    else if(!strcmp(argv[1],"missing-key") && argc==3)sn_tls_listener_bind("127.0.0.1:0",argv[2],"missing.key");
    else if(!strcmp(argv[1],"connect") && argc==3)sn_tls_stream_connect(argv[2]);
    else return 2;
    return 0;
}
