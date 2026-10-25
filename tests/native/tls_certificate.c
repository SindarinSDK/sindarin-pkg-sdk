/* Ephemeral loopback credentials, using the same OpenSSL library as the SDK.
 * No openssl executable, persistent trust-store change or checked-in key. */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr,"certificate generation failed at %d\n",__LINE__); exit(1); } } while (0)

int main(int argc,char **argv)
{
    CHECK(argc==3);
    EVP_PKEY_CTX *context=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);CHECK(context);
    EVP_PKEY *key=NULL;
    CHECK(EVP_PKEY_keygen_init(context)>0);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(context,2048)>0);
    CHECK(EVP_PKEY_keygen(context,&key)>0);EVP_PKEY_CTX_free(context);
    X509 *certificate=X509_new();CHECK(certificate);
    CHECK(X509_set_version(certificate,2)==1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate),1)==1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate),-60));
    CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate),86400));
    CHECK(X509_set_pubkey(certificate,key)==1);
    X509_NAME *subject=X509_get_subject_name(certificate);
    CHECK(X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,(const unsigned char *)"localhost",-1,-1,0)==1);
    CHECK(X509_set_issuer_name(certificate,subject)==1);
    X509_EXTENSION *extension=X509V3_EXT_conf_nid(NULL,NULL,NID_subject_alt_name,"DNS:localhost");CHECK(extension);
    CHECK(X509_add_ext(certificate,extension,-1)==1);X509_EXTENSION_free(extension);
    CHECK(X509_sign(certificate,key,EVP_sha256())>0);
    FILE *output=fopen(argv[1],"wb");CHECK(output);
    CHECK(PEM_write_X509(output,certificate)==1);CHECK(fclose(output)==0);
    output=fopen(argv[2],"wb");CHECK(output);
    CHECK(PEM_write_PrivateKey(output,key,NULL,NULL,0,NULL,NULL)==1);CHECK(fclose(output)==0);
    X509_free(certificate);EVP_PKEY_free(key);
    return 0;
}
