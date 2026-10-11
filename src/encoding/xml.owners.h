/* Private document ownership registry; public Xml fields retain their layout. */
typedef struct SnXmlWrapperOwner {
    SnXml *wrapper;
    struct SnXmlWrapperOwner *next;
} SnXmlWrapperOwner;
typedef struct SnXmlDocumentOwner {
    xmlDocPtr document;
    SnXmlWrapperOwner *wrappers;
    struct SnXmlDocumentOwner *next;
} SnXmlDocumentOwner;
static SnXmlDocumentOwner *sn_xml_documents;
static pthread_mutex_t sn_xml_owner_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sn_xml_owner_attach(SnXml *wrapper, xmlDocPtr document)
{
    if (!document) return;
    SnXmlWrapperOwner *entry = calloc(1, sizeof(*entry));
    if (!entry) abort();
    entry->wrapper = wrapper;
    pthread_mutex_lock(&sn_xml_owner_mutex);
    SnXmlDocumentOwner *owner = sn_xml_documents;
    while (owner && owner->document != document) owner = owner->next;
    if (!owner) {
        owner = calloc(1, sizeof(*owner));
        if (!owner) abort();
        owner->document = document;
        owner->next = sn_xml_documents;
        sn_xml_documents = owner;
    }
    entry->next = owner->wrappers;
    owner->wrappers = entry;
    pthread_mutex_unlock(&sn_xml_owner_mutex);
}

static void sn_xml_owner_detach(SnXml *wrapper)
{
    xmlDocPtr dead_document = NULL;
    pthread_mutex_lock(&sn_xml_owner_mutex);
    SnXmlDocumentOwner **owners = &sn_xml_documents;
    while (*owners) {
        SnXmlDocumentOwner *owner = *owners;
        SnXmlWrapperOwner **entries = &owner->wrappers;
        while (*entries && (*entries)->wrapper != wrapper) entries = &(*entries)->next;
        if (*entries) {
            SnXmlWrapperOwner *entry = *entries;
            *entries = entry->next;
            free(entry);
            if (!owner->wrappers) {
                *owners = owner->next;
                dead_document = owner->document;
                free(owner);
            }
            break;
        }
        owners = &owner->next;
    }
    wrapper->doc = 0;
    wrapper->node = 0;
    pthread_mutex_unlock(&sn_xml_owner_mutex);
    /* Publish removal before libxml callbacks can reenter the SDK. */
    if (dead_document) xmlFreeDoc(dead_document);
}

static void sn_xml_invalidate_subtree(xmlDocPtr document, xmlNodePtr removed)
{
    pthread_mutex_lock(&sn_xml_owner_mutex);
    for (SnXmlDocumentOwner *owner = sn_xml_documents; owner; owner = owner->next) {
        if (owner->document != document) continue;
        for (SnXmlWrapperOwner *entry = owner->wrappers; entry; entry = entry->next) {
            xmlNodePtr node = (xmlNodePtr)(uintptr_t)entry->wrapper->node;
            for (xmlNodePtr parent = node; parent; parent = parent->parent) {
                if (parent == removed) { entry->wrapper->node = 0; break; }
            }
        }
        break;
    }
    pthread_mutex_unlock(&sn_xml_owner_mutex);
}

static void sn_xml_retarget_node(xmlDocPtr document, xmlNodePtr original, xmlNodePtr replacement)
{
    pthread_mutex_lock(&sn_xml_owner_mutex);
    for (SnXmlDocumentOwner *owner = sn_xml_documents; owner; owner = owner->next) {
        if (owner->document != document) continue;
        for (SnXmlWrapperOwner *entry = owner->wrappers; entry; entry = entry->next)
            if (entry->wrapper->node == (long long)(uintptr_t)original)
                entry->wrapper->node = (long long)(uintptr_t)replacement;
        break;
    }
    pthread_mutex_unlock(&sn_xml_owner_mutex);
}

static SnXml *sn_xml_wrapper_retain(SnXml *value)
{
    if (value) __atomic_fetch_add(&value->__rc__, 1, __ATOMIC_RELAXED);
    return value;
}
static void sn_xml_wrapper_release(SnXml *value)
{
    if (value && __atomic_sub_fetch(&value->__rc__, 1, __ATOMIC_ACQ_REL) == 0) {
        sn_xml_owner_detach(value);
        free(value);
    }
}
static void sn_xml_array_release(void *slot) { sn_xml_wrapper_release(*(SnXml **)slot); }
static void sn_xml_array_copy(const void *source, void *destination)
{
    *(SnXml **)destination = sn_xml_wrapper_retain(*(SnXml *const *)source);
}
