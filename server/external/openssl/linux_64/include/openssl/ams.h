/*
 * Copyright 2008-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_AMS_H
# define HEADER_AMS_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_AMS
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/amserr.h>
# ifdef __cplusplus
extern "C" {
# endif

typedef struct AMS_ContentInfo_st AMS_ContentInfo;
typedef struct AMS_SignerInfo_st AMS_SignerInfo;
typedef struct AMS_CertificateChoices AMS_CertificateChoices;
typedef struct AMS_RevocationInfoChoice_st AMS_RevocationInfoChoice;
typedef struct AMS_RecipientInfo_st AMS_RecipientInfo;
typedef struct AMS_ReceiptRequest_st AMS_ReceiptRequest;
typedef struct AMS_Receipt_st AMS_Receipt;
typedef struct AMS_RecipientEncryptedKey_st AMS_RecipientEncryptedKey;
typedef struct AMS_OtherKeyAttribute_st AMS_OtherKeyAttribute;

DEFINE_STACK_OF(AMS_SignerInfo)
DEFINE_STACK_OF(AMS_RecipientEncryptedKey)
DEFINE_STACK_OF(AMS_RecipientInfo)
DEFINE_STACK_OF(AMS_RevocationInfoChoice)
DECLARE_ASN1_FUNCTIONS(AMS_ContentInfo)
DECLARE_ASN1_FUNCTIONS(AMS_ReceiptRequest)
DECLARE_ASN1_PRINT_FUNCTION(AMS_ContentInfo)

# define AMS_SIGNERINFO_ISSUER_SERIAL    0
# define AMS_SIGNERINFO_KEYIDENTIFIER    1

# define AMS_RECIPINFO_NONE              -1
# define AMS_RECIPINFO_TRANS             0
# define AMS_RECIPINFO_AGREE             1
# define AMS_RECIPINFO_KEK               2
# define AMS_RECIPINFO_PASS              3
# define AMS_RECIPINFO_OTHER             4

/* S/MIME related flags */

# define AMS_TEXT                        0x1
# define AMS_NOCERTS                     0x2
# define AMS_NO_CONTENT_VERIFY           0x4
# define AMS_NO_ATTR_VERIFY              0x8
# define AMS_NOSIGS                      \
                        (AMS_NO_CONTENT_VERIFY|AMS_NO_ATTR_VERIFY)
# define AMS_NOINTERN                    0x10
# define AMS_NO_SIGNER_CERT_VERIFY       0x20
# define AMS_NOVERIFY                    0x20
# define AMS_DETACHED                    0x40
# define AMS_BINARY                      0x80
# define AMS_NOATTR                      0x100
# define AMS_NOSMIMECAP                  0x200
# define AMS_NOOLDMIMETYPE               0x400
# define AMS_CRLFEOL                     0x800
# define AMS_STREAM                      0x1000
# define AMS_NOCRL                       0x2000
# define AMS_PARTIAL                     0x4000
# define AMS_REUSE_DIGEST                0x8000
# define AMS_USE_KEYID                   0x10000
# define AMS_DEBUG_DECRYPT               0x20000
# define AMS_KEY_PARAM                   0x40000
# define AMS_ASCIICRLF                   0x80000

const ASN1_OBJECT *AMS_get0_type(const AMS_ContentInfo *ams);

BIO *AMS_dataInit(AMS_ContentInfo *ams, BIO *icont);
int AMS_dataFinal(AMS_ContentInfo *ams, BIO *bio);

ASN1_OCTET_STRING **AMS_get0_content(AMS_ContentInfo *ams);
int AMS_is_detached(AMS_ContentInfo *ams);
int AMS_set_detached(AMS_ContentInfo *ams, int detached);

# ifdef HEADER_PEM_H
DECLARE_PEM_rw_const(AMS, AMS_ContentInfo)
# endif
int AMS_stream(unsigned char ***boundary, AMS_ContentInfo *ams);
AMS_ContentInfo *d2i_AMS_bio(BIO *bp, AMS_ContentInfo **ams);
int i2d_AMS_bio(BIO *bp, AMS_ContentInfo *ams);

BIO *BIO_new_AMS(BIO *out, AMS_ContentInfo *ams);
int i2d_AMS_bio_stream(BIO *out, AMS_ContentInfo *ams, BIO *in, int flags);
int PEM_write_bio_AMS_stream(BIO *out, AMS_ContentInfo *ams, BIO *in,
                             int flags);
AMS_ContentInfo *SMIME_read_AMS(BIO *bio, BIO **bcont);
int SMIME_write_AMS(BIO *bio, AMS_ContentInfo *ams, BIO *data, int flags);

int AMS_final(AMS_ContentInfo *ams, BIO *data, BIO *dcont,
              unsigned int flags);

AMS_ContentInfo *AMS_sign(X509 *signcert, EVP_PKEY *pkey,
                          STACK_OF(X509) *certs, BIO *data,
                          unsigned int flags);

AMS_ContentInfo *AMS_sign_receipt(AMS_SignerInfo *si,
                                  X509 *signcert, EVP_PKEY *pkey,
                                  STACK_OF(X509) *certs, unsigned int flags);

int AMS_data(AMS_ContentInfo *ams, BIO *out, unsigned int flags);
AMS_ContentInfo *AMS_data_create(BIO *in, unsigned int flags);

int AMS_digest_verify(AMS_ContentInfo *ams, BIO *dcont, BIO *out,
                      unsigned int flags);
AMS_ContentInfo *AMS_digest_create(BIO *in, const EVP_MD *md,
                                   unsigned int flags);

int AMS_EncryptedData_decrypt(AMS_ContentInfo *ams,
                              const unsigned char *key, size_t keylen,
                              BIO *dcont, BIO *out, unsigned int flags);

AMS_ContentInfo *AMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
                                           const unsigned char *key,
                                           size_t keylen, unsigned int flags);

int AMS_EncryptedData_set1_key(AMS_ContentInfo *ams, const EVP_CIPHER *ciph,
                               const unsigned char *key, size_t keylen);

int AMS_verify(AMS_ContentInfo *ams, STACK_OF(X509) *certs,
               X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);

int AMS_verify_receipt(AMS_ContentInfo *rams, AMS_ContentInfo *oams,
                       STACK_OF(X509) *certs,
                       X509_STORE *store, unsigned int flags);

STACK_OF(X509) *AMS_get0_signers(AMS_ContentInfo *ams);

AMS_ContentInfo *AMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);

int AMS_decrypt(AMS_ContentInfo *ams, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);

int AMS_decrypt_set1_pkey(AMS_ContentInfo *ams, EVP_PKEY *pk, X509 *cert);
int AMS_decrypt_set1_key(AMS_ContentInfo *ams,
                         unsigned char *key, size_t keylen,
                         const unsigned char *id, size_t idlen);
int AMS_decrypt_set1_password(AMS_ContentInfo *ams,
                              unsigned char *pass, ossl_ssize_t passlen);

STACK_OF(AMS_RecipientInfo) *AMS_get0_RecipientInfos(AMS_ContentInfo *ams);
int AMS_RecipientInfo_type(AMS_RecipientInfo *ri);
EVP_PKEY_CTX *AMS_RecipientInfo_get0_pkey_ctx(AMS_RecipientInfo *ri);
AMS_ContentInfo *AMS_EnvelopedData_create(const EVP_CIPHER *cipher);
AMS_RecipientInfo *AMS_add1_recipient_cert(AMS_ContentInfo *ams,
                                           X509 *recip, unsigned int flags);
int AMS_RecipientInfo_set0_pkey(AMS_RecipientInfo *ri, EVP_PKEY *pkey);
int AMS_RecipientInfo_ktri_cert_cmp(AMS_RecipientInfo *ri, X509 *cert);
int AMS_RecipientInfo_ktri_get0_algs(AMS_RecipientInfo *ri,
                                     EVP_PKEY **pk, X509 **recip,
                                     X509_ALGOR **palg);
int AMS_RecipientInfo_ktri_get0_signer_id(AMS_RecipientInfo *ri,
                                          ASN1_OCTET_STRING **keyid,
                                          X509_NAME **issuer,
                                          ASN1_INTEGER **sno);

AMS_RecipientInfo *AMS_add0_recipient_key(AMS_ContentInfo *ams, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType);

int AMS_RecipientInfo_kekri_get0_id(AMS_RecipientInfo *ri,
                                    X509_ALGOR **palg,
                                    ASN1_OCTET_STRING **pid,
                                    ASN1_GENERALIZEDTIME **pdate,
                                    ASN1_OBJECT **potherid,
                                    ASN1_TYPE **pothertype);

int AMS_RecipientInfo_set0_key(AMS_RecipientInfo *ri,
                               unsigned char *key, size_t keylen);

int AMS_RecipientInfo_kekri_id_cmp(AMS_RecipientInfo *ri,
                                   const unsigned char *id, size_t idlen);

int AMS_RecipientInfo_set0_password(AMS_RecipientInfo *ri,
                                    unsigned char *pass,
                                    ossl_ssize_t passlen);

AMS_RecipientInfo *AMS_add0_recipient_password(AMS_ContentInfo *ams,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph);

int AMS_RecipientInfo_decrypt(AMS_ContentInfo *ams, AMS_RecipientInfo *ri);
int AMS_RecipientInfo_encrypt(AMS_ContentInfo *ams, AMS_RecipientInfo *ri);

int AMS_uncompress(AMS_ContentInfo *ams, BIO *dcont, BIO *out,
                   unsigned int flags);
AMS_ContentInfo *AMS_compress(BIO *in, int comp_nid, unsigned int flags);

int AMS_set1_eContentType(AMS_ContentInfo *ams, const ASN1_OBJECT *oid);
const ASN1_OBJECT *AMS_get0_eContentType(AMS_ContentInfo *ams);

AMS_CertificateChoices *AMS_add0_CertificateChoices(AMS_ContentInfo *ams);
int AMS_add0_cert(AMS_ContentInfo *ams, X509 *cert);
int AMS_add1_cert(AMS_ContentInfo *ams, X509 *cert);
STACK_OF(X509) *AMS_get1_certs(AMS_ContentInfo *ams);

AMS_RevocationInfoChoice *AMS_add0_RevocationInfoChoice(AMS_ContentInfo *ams);
int AMS_add0_crl(AMS_ContentInfo *ams, X509_CRL *crl);
int AMS_add1_crl(AMS_ContentInfo *ams, X509_CRL *crl);
STACK_OF(X509_CRL) *AMS_get1_crls(AMS_ContentInfo *ams);

int AMS_SignedData_init(AMS_ContentInfo *ams);
AMS_SignerInfo *AMS_add1_signer(AMS_ContentInfo *ams,
                                X509 *signer, EVP_PKEY *pk, const EVP_MD *md,
                                unsigned int flags);
EVP_PKEY_CTX *AMS_SignerInfo_get0_pkey_ctx(AMS_SignerInfo *si);
EVP_MD_CTX *AMS_SignerInfo_get0_md_ctx(AMS_SignerInfo *si);
STACK_OF(AMS_SignerInfo) *AMS_get0_SignerInfos(AMS_ContentInfo *ams);

void AMS_SignerInfo_set1_signer_cert(AMS_SignerInfo *si, X509 *signer);
int AMS_SignerInfo_get0_signer_id(AMS_SignerInfo *si,
                                  ASN1_OCTET_STRING **keyid,
                                  X509_NAME **issuer, ASN1_INTEGER **sno);
int AMS_SignerInfo_cert_cmp(AMS_SignerInfo *si, X509 *cert);
int AMS_set1_signers_certs(AMS_ContentInfo *ams, STACK_OF(X509) *certs,
                           unsigned int flags);
void AMS_SignerInfo_get0_algs(AMS_SignerInfo *si, EVP_PKEY **pk,
                              X509 **signer, X509_ALGOR **pdig,
                              X509_ALGOR **psig);
ASN1_OCTET_STRING *AMS_SignerInfo_get0_signature(AMS_SignerInfo *si);
int AMS_SignerInfo_sign(AMS_SignerInfo *si);
int AMS_SignerInfo_verify(AMS_SignerInfo *si);
int AMS_SignerInfo_verify_content(AMS_SignerInfo *si, BIO *chain);

int AMS_add_smimecap(AMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs);
int AMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs,
                            int algnid, int keysize);
int AMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap);

int AMS_signed_get_attr_count(const AMS_SignerInfo *si);
int AMS_signed_get_attr_by_NID(const AMS_SignerInfo *si, int nid,
                               int lastpos);
int AMS_signed_get_attr_by_OBJ(const AMS_SignerInfo *si, const ASN1_OBJECT *obj,
                               int lastpos);
X509_ATTRIBUTE *AMS_signed_get_attr(const AMS_SignerInfo *si, int loc);
X509_ATTRIBUTE *AMS_signed_delete_attr(AMS_SignerInfo *si, int loc);
int AMS_signed_add1_attr(AMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int AMS_signed_add1_attr_by_OBJ(AMS_SignerInfo *si,
                                const ASN1_OBJECT *obj, int type,
                                const void *bytes, int len);
int AMS_signed_add1_attr_by_NID(AMS_SignerInfo *si,
                                int nid, int type,
                                const void *bytes, int len);
int AMS_signed_add1_attr_by_txt(AMS_SignerInfo *si,
                                const char *attrname, int type,
                                const void *bytes, int len);
void *AMS_signed_get0_data_by_OBJ(AMS_SignerInfo *si, const ASN1_OBJECT *oid,
                                  int lastpos, int type);

int AMS_unsigned_get_attr_count(const AMS_SignerInfo *si);
int AMS_unsigned_get_attr_by_NID(const AMS_SignerInfo *si, int nid,
                                 int lastpos);
int AMS_unsigned_get_attr_by_OBJ(const AMS_SignerInfo *si,
                                 const ASN1_OBJECT *obj, int lastpos);
X509_ATTRIBUTE *AMS_unsigned_get_attr(const AMS_SignerInfo *si, int loc);
X509_ATTRIBUTE *AMS_unsigned_delete_attr(AMS_SignerInfo *si, int loc);
int AMS_unsigned_add1_attr(AMS_SignerInfo *si, X509_ATTRIBUTE *attr);
int AMS_unsigned_add1_attr_by_OBJ(AMS_SignerInfo *si,
                                  const ASN1_OBJECT *obj, int type,
                                  const void *bytes, int len);
int AMS_unsigned_add1_attr_by_NID(AMS_SignerInfo *si,
                                  int nid, int type,
                                  const void *bytes, int len);
int AMS_unsigned_add1_attr_by_txt(AMS_SignerInfo *si,
                                  const char *attrname, int type,
                                  const void *bytes, int len);
void *AMS_unsigned_get0_data_by_OBJ(AMS_SignerInfo *si, ASN1_OBJECT *oid,
                                    int lastpos, int type);

int AMS_get1_ReceiptRequest(AMS_SignerInfo *si, AMS_ReceiptRequest **prr);
AMS_ReceiptRequest *AMS_ReceiptRequest_create0(unsigned char *id, int idlen,
                                               int allorfirst,
                                               STACK_OF(GENERAL_NAMES)
                                               *receiptList, STACK_OF(GENERAL_NAMES)
                                               *receiptsTo);
int AMS_add1_ReceiptRequest(AMS_SignerInfo *si, AMS_ReceiptRequest *rr);
void AMS_ReceiptRequest_get0_values(AMS_ReceiptRequest *rr,
                                    ASN1_STRING **pcid,
                                    int *pallorfirst,
                                    STACK_OF(GENERAL_NAMES) **plist,
                                    STACK_OF(GENERAL_NAMES) **prto);
int AMS_RecipientInfo_kari_get0_alg(AMS_RecipientInfo *ri,
                                    X509_ALGOR **palg,
                                    ASN1_OCTET_STRING **pukm);
STACK_OF(AMS_RecipientEncryptedKey)
*AMS_RecipientInfo_kari_get0_reks(AMS_RecipientInfo *ri);

int AMS_RecipientInfo_kari_get0_orig_id(AMS_RecipientInfo *ri,
                                        X509_ALGOR **pubalg,
                                        ASN1_BIT_STRING **pubkey,
                                        ASN1_OCTET_STRING **keyid,
                                        X509_NAME **issuer,
                                        ASN1_INTEGER **sno);

int AMS_RecipientInfo_kari_orig_id_cmp(AMS_RecipientInfo *ri, X509 *cert);

int AMS_RecipientEncryptedKey_get0_id(AMS_RecipientEncryptedKey *rek,
                                      ASN1_OCTET_STRING **keyid,
                                      ASN1_GENERALIZEDTIME **tm,
                                      AMS_OtherKeyAttribute **other,
                                      X509_NAME **issuer, ASN1_INTEGER **sno);
int AMS_RecipientEncryptedKey_cert_cmp(AMS_RecipientEncryptedKey *rek,
                                       X509 *cert);
int AMS_RecipientInfo_kari_set0_pkey(AMS_RecipientInfo *ri, EVP_PKEY *pk);
EVP_CIPHER_CTX *AMS_RecipientInfo_kari_get0_ctx(AMS_RecipientInfo *ri);
int AMS_RecipientInfo_kari_decrypt(AMS_ContentInfo *ams,
                                   AMS_RecipientInfo *ri,
                                   AMS_RecipientEncryptedKey *rek);

int AMS_SharedInfo_encode(unsigned char **pder, X509_ALGOR *kekalg,
                          ASN1_OCTET_STRING *ukm, int keylen);

/* Backward compatibility for spelling errors. */
# define AMS_R_UNKNOWN_DIGEST_ALGORITM AMS_R_UNKNOWN_DIGEST_ALGORITHM
# define AMS_R_UNSUPPORTED_RECPIENTINFO_TYPE \
    AMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
