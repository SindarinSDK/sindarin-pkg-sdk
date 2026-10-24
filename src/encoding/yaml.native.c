/* Canonical C Yaml storage; parsing and mutation stay in yaml.sn.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define SN_SDK_YAML_STANDALONE 1
#include "yaml.sn.c"

SnSdkYamlRecord *sn_sdk_yaml_create(void) { return sn_sdk_yaml_new(); }
SnSdkYamlRecord *sn_sdk_yaml_retain(SnSdkYamlRecord *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
void sn_sdk_yaml_release(SnSdkYamlRecord *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) {
        sn_yaml_node_free(YAML_NODE(value));
        free(value);
    }
}
int sn_sdk_yaml_refs(SnSdkYamlRecord *value)
{
    return value ? __atomic_load_n(&value->__rc__, __ATOMIC_RELAXED) : 0;
}
SnSdkYamlRecord *sn_sdk_yaml_copy(const SnSdkYamlRecord *value)
{
    return sn_yaml_copy((SnSdkYamlRecord *)value);
}
