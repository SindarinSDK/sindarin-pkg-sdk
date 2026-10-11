#undef NDEBUG
#define SN_SDK_XML_STANDALONE 1
#include "xml.native.h"
#include "sn_abi.h"
#include <libxml/tree.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static xmlDocPtr watched_document;
static int documents_destroyed, wires_destroyed, cleanup_reentries;
static xmlDeregisterNodeFunc previous_deregister;
static void observe_node(xmlNodePtr node)
{
    if ((void *)node == (void *)watched_document) {
        documents_destroyed++;
        if (cleanup_reentries == 0) {
            cleanup_reentries++;
            SnSdkXmlRecord *reentered = sn_xml_parse("<reentered/>");
            sn_sdk_xml_release(reentered);
        }
    }
    if (previous_deregister) previous_deregister(node);
}
static void destroy_wire(void *pointer, uintptr_t context)
{
    assert(context == 43);
    wires_destroyed++;
    sn_sdk_xml_release(pointer);
}
static void expect_name(SnSdkXmlRecord *value, const char *expected)
{
    char *name = sn_xml_name(value);
    assert(!strcmp(name, expected));
    free(name);
}
int main(void)
{
    _Static_assert(sizeof(SnSdkXmlRecord) == 40, "Xml canonical layout");
    assert(sn_sdk_xml_refs(NULL) == 0 && sn_sdk_xml_retain(NULL) == NULL);
    sn_sdk_xml_release(NULL);
    SnSdkXmlRecord *empty = sn_sdk_xml_copy(NULL);
    assert(empty && empty->doc == 0 && empty->node == 0 && empty->handle == 0);
    sn_sdk_xml_release(empty);
    SnSdkXmlRecord *root = sn_xml_parse("<root><child><leaf/></child></root>");
    watched_document = (xmlDocPtr)(uintptr_t)root->doc;
    previous_deregister = xmlDeregisterNodeDefault(observe_node);
    SnSdkXmlRecord *alias = sn_sdk_xml_retain(root);
    SnSdkXmlRecord *child = sn_xml_first_child(root);
    SnSdkXmlRecord *leaf = sn_xml_first_child(child);
    assert(child->doc == root->doc && child->handle == 0 && child->is_root == 0);
    SnSdkXmlRecord *copy = sn_sdk_xml_copy(root);
    assert(copy != root && copy->doc != root->doc && copy->node != root->node);
    SnSdkXmlRecord *copy_child = sn_xml_first_child(copy);
    sn_xml_set_name(copy_child, "copy");
    expect_name(child, "child");
    sn_sdk_xml_release(copy_child);
    sn_sdk_xml_release(copy);
    sn_sdk_xml_release(root);
    sn_xml_dispose(alias);
    sn_xml_dispose(alias);
    sn_sdk_xml_release(alias);
    assert(documents_destroyed == 0);
    expect_name(child, "child");
    expect_name(leaf, "leaf");
    sn_xml_remove(child);
    assert(child->node == 0 && leaf->node == 0);
    expect_name(leaf, "");
    sn_sdk_xml_release(child);
    assert(documents_destroyed == 0);
    SnAbiValue *wire = NULL;
    assert(sn_abi_v1_resource_new_typed("SindarinSDK/sindarin-pkg-sdk:encoding.Xml@1", leaf, destroy_wire, 43, &wire) == 0);
    SnAbiValue *credit = sn_abi_v1_retain(wire);
    sn_abi_v1_release(wire);
    assert(wires_destroyed == 0 && documents_destroyed == 0);
    sn_abi_v1_release(credit);
    assert(wires_destroyed == 1 && documents_destroyed == 1 && cleanup_reentries == 1);
    for (int i = 0; i < 40; i++) {
        root = sn_xml_parse("<root><one/><two/></root>");
        watched_document = (xmlDocPtr)(uintptr_t)root->doc;
        SnArray *children = sn_xml_children(root);
        SnArray *copied = sn_array_copy(children);
        assert(children->len == 2 && copied->len == 2);
        child = ((SnSdkXmlRecord **)children->data)[0];
        assert(child == ((SnSdkXmlRecord **)copied->data)[0] && sn_sdk_xml_refs(child) == 2);
        sn_sdk_xml_release(root);
        sn_array_free(children);
        expect_name(((SnSdkXmlRecord **)copied->data)[0], "one");
        assert(documents_destroyed == i + 1);
        sn_array_free(copied);
        assert(documents_destroyed == i + 2);
    }
    root = sn_xml_parse("<root><child><leaf/></child></root>");
    child = sn_xml_first_child(root);
    leaf = sn_xml_first_child(child);
    sn_xml_set_text(root, "replacement");
    assert(child->node == 0 && leaf->node == 0);
    sn_sdk_xml_release(child);
    sn_sdk_xml_release(leaf);
    sn_sdk_xml_release(root);
    root = sn_xml_parse("<root>A<child/>B</root>");
    SnSdkXmlRecord *moved = sn_xml_find(root, "/root/text()[1]");
    SnSdkXmlRecord *moved_alias = sn_xml_find(root, "/root/text()[1]");
    sn_xml_add_child(root, moved);
    char *merged_text = sn_xml_text(moved_alias);
    assert(!strcmp(merged_text, "BA"));
    free(merged_text);
    sn_sdk_xml_release(moved);
    sn_sdk_xml_release(moved_alias);
    sn_sdk_xml_release(root);
    xmlDeregisterNodeDefault(previous_deregister);
    puts("SDK canonical Xml: pass");
}
