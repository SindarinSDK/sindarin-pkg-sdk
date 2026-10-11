#undef NDEBUG
#define SN_SDK_PROCESS_STANDALONE 1
#include "process.native.h"
#include "sn_abi.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int destroyed;
static void destroy_process(void *value,uintptr_t context)
{
    assert(context==37);destroyed++;sn_sdk_process_release(value);
}
int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"--child")){fputs("captured stdout",stdout);fputs("captured stderr",stderr);return 7;}
    if(argc>1 && (!strcmp(argv[1],"--large-error") || !strcmp(argv[1],"--large-output"))) {
        FILE *first=!strcmp(argv[1],"--large-error") ? stderr : stdout;
        FILE *second=first==stderr ? stdout : stderr;
        for(int i=0;i<131072;i++) fputc(first==stderr ? 'E' : 'O',first);
        for(int i=0;i<131072;i++) fputc(second==stderr ? 'E' : 'O',second);
        return 7;
    }
    _Static_assert(sizeof(SnSdkProcessRecord)==24,"Process canonical layout");
    assert(sn_sdk_process_retain(NULL)==NULL && sn_sdk_process_refs(NULL)==0 && sn_sdk_process_copy(NULL)==NULL);sn_sdk_process_release(NULL);
    SnSdkProcessRecord *empty=sn_sdk_process_create();assert(empty && empty->stdout_str==NULL && sn_sdk_process_refs(empty)==1);sn_sdk_process_release(empty);
    SnArray *args=sn_array_new(sizeof(char *),1);char *arg="--child";sn_array_push(args,&arg);
    SnSdkProcessRecord *process=sn_process_run_args(argv[0],args);sn_array_free(args);
    assert(process && sn_sdk_process_refs(process)==1 && sn_process_get_exit_code(process)==7);
    assert(!strcmp(process->stdout_str,"captured stdout") && !strcmp(process->stderr_str,"captured stderr"));
    SnSdkProcessRecord *alias=sn_sdk_process_retain(process);assert(alias==process && sn_sdk_process_refs(process)==2);
    SnSdkProcessRecord *copy=sn_sdk_process_copy(process);assert(copy && copy!=process && copy->stdout_str!=process->stdout_str && copy->stderr_str!=process->stderr_str && copy->exit_code==7);
    copy->stdout_str[0]='X';assert(process->stdout_str[0]=='c');sn_sdk_process_release(copy);
    char *out=sn_process_get_stdout(alias),*err=sn_process_get_stderr(alias);
    SnAbiValue *wire=NULL;assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:os.Process@1",process,destroy_process,37,&wire)==0);
    SnAbiValue *credit=sn_abi_v1_retain(wire);sn_sdk_process_release(alias);sn_abi_v1_release(wire);assert(destroyed==0);
    void *pointer=NULL;assert(sn_abi_v1_resource_data_typed(credit,"SindarinSDK/sindarin-pkg-sdk:os.Process@1",&pointer)==0 && pointer==process && sn_sdk_process_refs(pointer)==1);
    sn_abi_v1_release(credit);assert(destroyed==1 && !strcmp(out,"captured stdout") && !strcmp(err,"captured stderr"));free(out);free(err);
    for(int i=0;i<40;i++){process=sn_sdk_process_create();process->stdout_str=strdup("owned output");process->stderr_str=strdup("owned error");assert(sn_sdk_process_refs(process)==1);sn_sdk_process_release(process);}
    for(int order=0;order<2;order++) {
        args=sn_array_new(sizeof(char *),1);arg=order ? "--large-output" : "--large-error";sn_array_push(args,&arg);
        process=sn_process_run_args(argv[0],args);sn_array_free(args);
        assert(process && process->exit_code==7 && strlen(process->stdout_str)==131072 && strlen(process->stderr_str)==131072);
        for(size_t i=0;i<131072;i++){assert(process->stdout_str[i]=='O');assert(process->stderr_str[i]=='E');}
        sn_sdk_process_release(process);
    }
    puts("SDK canonical Process: pass");
}
