/* Canonical Xml storage and credits; all DOM operations stay in C. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_XML_STANDALONE 1
#include "xml.sn.c"
SnSdkXmlRecord *sn_sdk_xml_create(void) { return sn_sdk_xml_new(); }
SnSdkXmlRecord *sn_sdk_xml_retain(SnSdkXmlRecord *value) { return sn_xml_wrapper_retain(value); }
void sn_sdk_xml_release(SnSdkXmlRecord *value) { sn_xml_wrapper_release(value); }
int sn_sdk_xml_refs(SnSdkXmlRecord *value) { return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0; }
SnSdkXmlRecord *sn_sdk_xml_copy(const SnSdkXmlRecord *value) { return sn_xml_copy((SnSdkXmlRecord *)value); }
