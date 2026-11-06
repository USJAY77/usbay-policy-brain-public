/* TEST ONLY: create a matching synthetic timestamp/CRL chain.
 * Keys exist only in EVP_PKEY memory. No key serialization API is called.
 * All output files contain PUBLIC test evidence. No runtime trust is adopted.
 */
#include <openssl/ts.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define CHECK(x) do { if (!(x)) goto done; } while (0)

static int extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL) return 0;
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}

static X509 *certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, int ca) {
    X509 *cert = X509_new();
    if (cert == NULL) return NULL;
    X509_NAME *name = X509_get_subject_name(cert);
    const char *cn = ca ? "USBAY SYNTHETIC TEST ROOT - NOT PRODUCTION" : "USBAY SYNTHETIC TEST TSA";
    if (X509_set_version(cert, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(cert),ca ? 1 : 2) != 1 ||
        X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)cn,-1,-1,0) != 1 ||
        X509_set_issuer_name(cert,issuer ? X509_get_subject_name(issuer) : name) != 1 ||
        X509_set_pubkey(cert,key) != 1 ||
        ASN1_TIME_set_string_X509(X509_getm_notBefore(cert),"20260101000000Z") != 1 ||
        ASN1_TIME_set_string_X509(X509_getm_notAfter(cert),"20270101000000Z") != 1 ||
        !extension(cert,issuer ? issuer : cert,NID_basic_constraints,ca ? "critical,CA:TRUE" : "critical,CA:FALSE") ||
        !extension(cert,issuer ? issuer : cert,NID_key_usage,ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature") ||
        !extension(cert,issuer ? issuer : cert,NID_subject_key_identifier,"hash") ||
        !extension(cert,issuer ? issuer : cert,NID_authority_key_identifier,"keyid:always") ||
        (!ca && !extension(cert,issuer,NID_ext_key_usage,"critical,timeStamping")) ||
        X509_sign(cert,issuer_key ? issuer_key : key,EVP_sha256()) <= 0) {
        X509_free(cert); return NULL;
    }
    return cert;
}

static int write_cert(const char *name, X509 *cert) {
    FILE *file = fopen(name,"wx");
    if (file == NULL) return 0;
    int ok = PEM_write_X509(file,cert);
    return fclose(file) == 0 && ok == 1;
}

static int write_crl(const char *name, X509 *root, EVP_PKEY *key, X509 *tsa, int revoked) {
    int ok = 0;
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *last = ASN1_TIME_new(), *next = ASN1_TIME_new();
    ASN1_INTEGER *number = ASN1_INTEGER_new();
    X509_REVOKED *entry = NULL;
    FILE *file = NULL;
    CHECK(crl && last && next && number);
    CHECK(X509_CRL_set_version(crl,1) == 1);
    CHECK(X509_CRL_set_issuer_name(crl,X509_get_subject_name(root)) == 1);
    CHECK(ASN1_TIME_set_string_X509(last,"20261106115900Z") == 1);
    CHECK(ASN1_TIME_set_string_X509(next,"20261107120000Z") == 1);
    CHECK(X509_CRL_set1_lastUpdate(crl,last) == 1 && X509_CRL_set1_nextUpdate(crl,next) == 1);
    CHECK(ASN1_INTEGER_set(number,revoked ? 2 : 1) == 1);
    CHECK(X509_CRL_add1_ext_i2d(crl,NID_crl_number,number,0,0) == 1);
    if (revoked) {
        entry=X509_REVOKED_new();CHECK(entry);
        CHECK(X509_REVOKED_set_serialNumber(entry,X509_get_serialNumber(tsa)) == 1);
        CHECK(X509_REVOKED_set_revocationDate(entry,last) == 1);
        CHECK(X509_CRL_add0_revoked(crl,entry) == 1);entry=NULL;
    }
    CHECK(X509_CRL_sort(crl) == 1);
    CHECK(X509_CRL_sign(crl,key,EVP_sha256()) > 0);
    file=fopen(name,"wx");CHECK(file);
    CHECK(PEM_write_X509_CRL(file,crl) == 1);
    ok=1;
done:
    if (file && fclose(file) != 0) ok=0;
    X509_REVOKED_free(entry);X509_CRL_free(crl);ASN1_TIME_free(last);ASN1_TIME_free(next);ASN1_INTEGER_free(number);
    return ok;
}

static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data) {
    (void)ctx;(void)data;
    ASN1_INTEGER *value=ASN1_INTEGER_new();
    if (value && ASN1_INTEGER_set(value,1) != 1) { ASN1_INTEGER_free(value);return NULL; }
    return value;
}

static int time_cb(TS_RESP_CTX *ctx, void *data, long *seconds, long *microseconds) {
    (void)ctx;(void)data;
    *seconds=1793966400L;*microseconds=0;return 1;
}

int main(int argc, char **argv) {
    struct rlimit core_limit = {0,0};
    if (setrlimit(RLIMIT_CORE,&core_limit) != 0) return 1;
    umask(0077);
    int result=1;
    EVP_PKEY *root_key=NULL,*tsa_key=NULL;
    X509 *root=NULL,*tsa=NULL;
    TS_REQ *request=NULL;TS_MSG_IMPRINT *imprint=NULL;X509_ALGOR *algorithm=NULL;
    ASN1_OBJECT *policy=NULL;ASN1_INTEGER *nonce=NULL;
    TS_RESP_CTX *ctx=NULL;TS_RESP *response=NULL;
    BIO *request_bio=NULL;FILE *file=NULL;
    unsigned char digest[32];unsigned int digest_size=0;
    if (argc != 1 && argc != 2) goto done;
    root_key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    tsa_key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    CHECK(root_key && tsa_key);
    root=certificate(root_key,NULL,NULL,1);CHECK(root);
    tsa=certificate(tsa_key,root,root_key,0);CHECK(tsa);
    CHECK(write_cert("test-root.pem",root) && write_cert("test-tsa.pem",tsa));
    CHECK(write_crl("test-good.crl.pem",root,root_key,tsa,0));
    CHECK(write_crl("test-revoked.crl.pem",root,root_key,tsa,1));
    request=TS_REQ_new();imprint=TS_MSG_IMPRINT_new();algorithm=X509_ALGOR_new();
    policy=OBJ_txt2obj("1.2.3.4.1",1);nonce=ASN1_INTEGER_new();
    CHECK(request && imprint && algorithm && policy && nonce);
    if (argc == 1) {
        CHECK(EVP_Digest("hello",5,digest,&digest_size,EVP_sha256(),NULL) == 1 && digest_size == 32);
    } else {
        CHECK(strlen(argv[1]) == 64);
        for (int i=0;i<64;i++) CHECK((argv[1][i]>='0' && argv[1][i]<='9') || (argv[1][i]>='a' && argv[1][i]<='f'));
        long length=0;
        unsigned char *decoded=OPENSSL_hexstr2buf(argv[1],&length);
        CHECK(decoded);
        if (length!=32) { OPENSSL_free(decoded);goto done; }
        memcpy(digest,decoded,32);OPENSSL_free(decoded);
    }
    X509_ALGOR_set0(algorithm,OBJ_nid2obj(NID_sha256),V_ASN1_NULL,NULL);
    CHECK(TS_MSG_IMPRINT_set_algo(imprint,algorithm) == 1);
    CHECK(TS_MSG_IMPRINT_set_msg(imprint,digest,32) == 1);
    CHECK(TS_REQ_set_version(request,1) == 1 && TS_REQ_set_msg_imprint(request,imprint) == 1);
    CHECK(TS_REQ_set_policy_id(request,policy) == 1 && ASN1_INTEGER_set(nonce,12345) == 1);
    CHECK(TS_REQ_set_nonce(request,nonce) == 1 && TS_REQ_set_cert_req(request,1) == 1);
    file=fopen("test-request.der","wx");CHECK(file);
    CHECK(i2d_TS_REQ_fp(file,request) == 1);
    int closed=fclose(file);file=NULL;CHECK(closed == 0);
    ctx=TS_RESP_CTX_new();request_bio=BIO_new_file("test-request.der","rb");CHECK(ctx && request_bio);
    CHECK(TS_RESP_CTX_set_signer_cert(ctx,tsa) == 1 && TS_RESP_CTX_set_signer_key(ctx,tsa_key) == 1);
    CHECK(TS_RESP_CTX_set_signer_digest(ctx,EVP_sha256()) == 1);
    CHECK(TS_RESP_CTX_set_ess_cert_id_digest(ctx,EVP_sha256()) == 1);
    CHECK(TS_RESP_CTX_set_def_policy(ctx,policy) == 1 && TS_RESP_CTX_add_md(ctx,EVP_sha256()) == 1);
    CHECK(TS_RESP_CTX_set_accuracy(ctx,1,0,0) == 1);
    TS_RESP_CTX_set_serial_cb(ctx,serial_cb,NULL);TS_RESP_CTX_set_time_cb(ctx,time_cb,NULL);
    response=TS_RESP_create_response(ctx,request_bio);CHECK(response && TS_RESP_get_tst_info(response));
    file=fopen("test-response.der","wx");CHECK(file);
    CHECK(i2d_TS_RESP_fp(file,response) == 1);
    closed=fclose(file);file=NULL;CHECK(closed == 0);
    result=0;
done:
    if (file) fclose(file);
    TS_RESP_free(response);TS_RESP_CTX_free(ctx);BIO_free(request_bio);
    TS_REQ_free(request);TS_MSG_IMPRINT_free(imprint);X509_ALGOR_free(algorithm);
    ASN1_OBJECT_free(policy);ASN1_INTEGER_free(nonce);
    X509_free(tsa);X509_free(root);EVP_PKEY_free(tsa_key);EVP_PKEY_free(root_key);
    return result;
}
