#ifndef SN_SDK_PROCESS_NATIVE_H
#define SN_SDK_PROCESS_NATIVE_H
#include <stdint.h>
#include <stddef.h>
#include "sn_array.h"
typedef struct { int __rc__; int32_t exit_code; char *stdout_str; char *stderr_str; } SnSdkProcessRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkProcessRecord *sn_sdk_process_create(void);
SnSdkProcessRecord *sn_sdk_process_retain(SnSdkProcessRecord *);
SnSdkProcessRecord *sn_sdk_process_copy(const SnSdkProcessRecord *);
void sn_sdk_process_release(SnSdkProcessRecord *);
int sn_sdk_process_refs(SnSdkProcessRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_PROCESS_STANDALONE) && !defined(SN_SDK_PROCESS_OPERATIONS_DECLARED)
#define SN_SDK_PROCESS_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkProcessRecord *sn_process_run(char *cmd);
SnSdkProcessRecord *sn_process_run_args(char *cmd, SnArray *args);
long long sn_process_get_exit_code(SnSdkProcessRecord *proc);
char *sn_process_get_stdout(SnSdkProcessRecord *proc);
char *sn_process_get_stderr(SnSdkProcessRecord *proc);
#ifdef __cplusplus
}
#endif
#endif
