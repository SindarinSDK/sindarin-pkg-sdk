#ifndef SN_SDK_XML_NATIVE_H
#define SN_SDK_XML_NATIVE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sn_array.h"
#include "sn_string.h"
typedef struct { int __rc__; long long doc; long long node; int32_t is_root; long long handle; } SnSdkXmlRecord;
#ifdef __cplusplus
extern "C" {
#endif
SnSdkXmlRecord *sn_sdk_xml_create(void);
SnSdkXmlRecord *sn_sdk_xml_retain(SnSdkXmlRecord *);
SnSdkXmlRecord *sn_sdk_xml_copy(const SnSdkXmlRecord *);
void sn_sdk_xml_release(SnSdkXmlRecord *);
int sn_sdk_xml_refs(SnSdkXmlRecord *);
#ifdef __cplusplus
}
#endif
#endif
#if defined(SN_SDK_XML_STANDALONE) && !defined(SN_SDK_XML_OPERATIONS_DECLARED)
#define SN_SDK_XML_OPERATIONS_DECLARED 1
#ifdef __cplusplus
extern "C" {
#endif
SnSdkXmlRecord *sn_xml_parse(char *text);
SnSdkXmlRecord *sn_xml_parse_file(char *path);
SnSdkXmlRecord *sn_xml_element(char *name);
SnSdkXmlRecord *sn_xml_document(char *rootName);
char *sn_xml_name(SnSdkXmlRecord *x);
char *sn_xml_text(SnSdkXmlRecord *x);
char *sn_xml_type_name(SnSdkXmlRecord *x);
bool sn_xml_is_element(SnSdkXmlRecord *x);
bool sn_xml_is_text(SnSdkXmlRecord *x);
bool sn_xml_is_document(SnSdkXmlRecord *x);
char *sn_xml_attr(SnSdkXmlRecord *x, char *name);
bool sn_xml_has_attr(SnSdkXmlRecord *x, char *name);
void sn_xml_set_attr(SnSdkXmlRecord *x, char *name, char *value);
void sn_xml_remove_attr(SnSdkXmlRecord *x, char *name);
SnArray *sn_xml_attrs(SnSdkXmlRecord *x);
SnArray *sn_xml_children(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_first_child(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_last_child(SnSdkXmlRecord *x);
long long sn_xml_child_count(SnSdkXmlRecord *x);
bool sn_xml_has_children(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_parent(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_next(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_prev(SnSdkXmlRecord *x);
SnSdkXmlRecord *sn_xml_find(SnSdkXmlRecord *x, char *xpath);
SnArray *sn_xml_find_all(SnSdkXmlRecord *x, char *xpath);
void sn_xml_add_child(SnSdkXmlRecord *x, SnSdkXmlRecord *child);
void sn_xml_set_text(SnSdkXmlRecord *x, char *content);
void sn_xml_set_name(SnSdkXmlRecord *x, char *name);
void sn_xml_remove(SnSdkXmlRecord *x);
char *sn_xml_to_string(SnSdkXmlRecord *x);
char *sn_xml_to_pretty_string(SnSdkXmlRecord *x);
void sn_xml_write_file(SnSdkXmlRecord *x, char *path);
void sn_xml_write_file_pretty(SnSdkXmlRecord *x, char *path);
SnSdkXmlRecord *sn_xml_copy(SnSdkXmlRecord *x);
void sn_xml_dispose(SnSdkXmlRecord *x);
#ifdef __cplusplus
}
#endif
#endif
