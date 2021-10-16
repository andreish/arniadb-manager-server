/* crypto/ams/ams.h */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */


#ifndef HEADER_AMS_H
#define HEADER_AMS_H

#include <openssl/x509.h>

#ifdef OPENSSL_NO_AMS
#error AMS is disabled.
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct AMS_ContentInfo_st AMS_ContentInfo;
typedef struct AMS_SignerInfo_st AMS_SignerInfo;
typedef struct AMS_CertificateChoices AMS_CertificateChoices;
typedef struct AMS_RevocationInfoChoice_st AMS_RevocationInfoChoice;
typedef struct AMS_RecipientInfo_st AMS_RecipientInfo;
typedef struct AMS_ReceiptRequest_st AMS_ReceiptRequest;
typedef struct AMS_Receipt_st AMS_Receipt;

DECLARE_STACK_OF(AMS_SignerInfo)
DECLARE_STACK_OF(GENERAL_NAMES)
DECLARE_ASN1_FUNCTIONS(AMS_ContentInfo)
DECLARE_ASN1_FUNCTIONS(AMS_ReceiptRequest)
DECLARE_ASN1_PRINT_FUNCTION(AMS_ContentInfo)

#define AMS_SIGNERINFO_ISSUER_SERIAL	0
#define AMS_SIGNERINFO_KEYIDENTIFIER	1

#define AMS_RECIPINFO_TRANS		0
#define AMS_RECIPINFO_AGREE		1
#define AMS_RECIPINFO_KEK		2
#define AMS_RECIPINFO_PASS		3
#define AMS_RECIPINFO_OTHER		4

/* S/MIME related flags */

#define AMS_TEXT			0x1
#define AMS_NOCERTS			0x2
#define AMS_NO_CONTENT_VERIFY		0x4
#define AMS_NO_ATTR_VERIFY		0x8
#define AMS_NOSIGS			\
			(AMS_NO_CONTENT_VERIFY|AMS_NO_ATTR_VERIFY)
#define AMS_NOINTERN			0x10
#define AMS_NO_SIGNER_CERT_VERIFY	0x20
#define AMS_NOVERIFY			0x20
#define AMS_DETACHED			0x40
#define AMS_BINARY			0x80
#define AMS_NOATTR			0x100
#define	AMS_NOSMIMECAP			0x200
#define AMS_NOOLDMIMETYPE		0x400
#define AMS_CRLFEOL			0x800
#define AMS_STREAM			0x1000
#define AMS_NOCRL			0x2000
#define AMS_PARTIAL			0x4000
#define AMS_REUSE_DIGEST		0x8000
#define AMS_USE_KEYID			0x10000
#define AMS_DEBUG_DECRYPT		0x20000

const ASN1_OBJECT *AMS_get0_type(AMS_ContentInfo *ams);

BIO *AMS_dataInit(AMS_ContentInfo *ams, BIO *icont);
int AMS_dataFinal(AMS_ContentInfo *ams, BIO *bio);

ASN1_OCTET_STRING **AMS_get0_content(AMS_ContentInfo *ams);
int AMS_is_detached(AMS_ContentInfo *ams);
int AMS_set_detached(AMS_ContentInfo *ams, int detached);

#ifdef HEADER_PEM_H
DECLARE_PEM_rw_const(AMS, AMS_ContentInfo)
#endif

int AMS_stream(unsigned char ***boundary, AMS_ContentInfo *ams);
AMS_ContentInfo *d2i_AMS_bio(BIO *bp, AMS_ContentInfo **ams);
int i2d_AMS_bio(BIO *bp, AMS_ContentInfo *ams);

BIO *BIO_new_AMS(BIO *out, AMS_ContentInfo *ams);
int i2d_AMS_bio_stream(BIO *out, AMS_ContentInfo *ams, BIO *in, int flags);
int PEM_write_bio_AMS_stream(BIO *out, AMS_ContentInfo *ams, BIO *in, int flags);
AMS_ContentInfo *SMIME_read_AMS(BIO *bio, BIO **bcont);
int SMIME_write_AMS(BIO *bio, AMS_ContentInfo *ams, BIO *data, int flags);

int AMS_final(AMS_ContentInfo *ams, BIO *data, BIO *dcont, unsigned int flags);

AMS_ContentInfo *AMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
						BIO *data, unsigned int flags);

AMS_ContentInfo *AMS_sign_receipt(AMS_SignerInfo *si,
					X509 *signcert, EVP_PKEY *pkey,
					STACK_OF(X509) *certs,
					unsigned int flags);

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
					const unsigned char *key, size_t keylen,
					unsigned int flags);

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
				BIO *dcont, BIO *out,
				unsigned int flags);
	
int AMS_decrypt_set1_pkey(AMS_ContentInfo *ams, EVP_PKEY *pk, X509 *cert);
int AMS_decrypt_set1_key(AMS_ContentInfo *ams, 
				unsigned char *key, size_t keylen,
				unsigned char *id, size_t idlen);
int AMS_decrypt_set1_password(AMS_ContentInfo *ams, 
				unsigned char *pass, ossl_ssize_t passlen);

STACK_OF(AMS_RecipientInfo) *AMS_get0_RecipientInfos(AMS_ContentInfo *ams);
int AMS_RecipientInfo_type(AMS_RecipientInfo *ri);
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
					X509_NAME **issuer, ASN1_INTEGER **sno);

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
					int iter, int wrap_nid, int pbe_nid,
					unsigned char *pass,
					ossl_ssize_t passlen,
					const EVP_CIPHER *kekciph);

int AMS_RecipientInfo_decrypt(AMS_ContentInfo *ams, AMS_RecipientInfo *ri);
	
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
STACK_OF(AMS_SignerInfo) *AMS_get0_SignerInfos(AMS_ContentInfo *ams);

void AMS_SignerInfo_set1_signer_cert(AMS_SignerInfo *si, X509 *signer);
int AMS_SignerInfo_get0_signer_id(AMS_SignerInfo *si,
					ASN1_OCTET_STRING **keyid,
					X509_NAME **issuer, ASN1_INTEGER **sno);
int AMS_SignerInfo_cert_cmp(AMS_SignerInfo *si, X509 *cert);
int AMS_set1_signers_certs(AMS_ContentInfo *ams, STACK_OF(X509) *certs,
					unsigned int flags);
void AMS_SignerInfo_get0_algs(AMS_SignerInfo *si, EVP_PKEY **pk, X509 **signer,
					X509_ALGOR **pdig, X509_ALGOR **psig);
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
int AMS_signed_get_attr_by_OBJ(const AMS_SignerInfo *si, ASN1_OBJECT *obj,
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
void *AMS_signed_get0_data_by_OBJ(AMS_SignerInfo *si, ASN1_OBJECT *oid,
					int lastpos, int type);

int AMS_unsigned_get_attr_count(const AMS_SignerInfo *si);
int AMS_unsigned_get_attr_by_NID(const AMS_SignerInfo *si, int nid,
			  int lastpos);
int AMS_unsigned_get_attr_by_OBJ(const AMS_SignerInfo *si, ASN1_OBJECT *obj,
			  int lastpos);
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

#ifdef HEADER_X509V3_H

int AMS_get1_ReceiptRequest(AMS_SignerInfo *si, AMS_ReceiptRequest **prr);
AMS_ReceiptRequest *AMS_ReceiptRequest_create0(unsigned char *id, int idlen,
				int allorfirst,
				STACK_OF(GENERAL_NAMES) *receiptList,
				STACK_OF(GENERAL_NAMES) *receiptsTo);
int AMS_add1_ReceiptRequest(AMS_SignerInfo *si, AMS_ReceiptRequest *rr);
void AMS_ReceiptRequest_get0_values(AMS_ReceiptRequest *rr,
					ASN1_STRING **pcid,
					int *pallorfirst,
					STACK_OF(GENERAL_NAMES) **plist,
					STACK_OF(GENERAL_NAMES) **prto);

#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_AMS_strings(void);

/* Error codes for the AMS functions. */

/* Function codes. */
#define AMS_F_CHECK_CONTENT				 99
#define AMS_F_AMS_ADD0_CERT				 164
#define AMS_F_AMS_ADD0_RECIPIENT_KEY			 100
#define AMS_F_AMS_ADD0_RECIPIENT_PASSWORD		 165
#define AMS_F_AMS_ADD1_RECEIPTREQUEST			 158
#define AMS_F_AMS_ADD1_RECIPIENT_CERT			 101
#define AMS_F_AMS_ADD1_SIGNER				 102
#define AMS_F_AMS_ADD1_SIGNINGTIME			 103
#define AMS_F_AMS_COMPRESS				 104
#define AMS_F_AMS_COMPRESSEDDATA_CREATE			 105
#define AMS_F_AMS_COMPRESSEDDATA_INIT_BIO		 106
#define AMS_F_AMS_COPY_CONTENT				 107
#define AMS_F_AMS_COPY_MESSAGEDIGEST			 108
#define AMS_F_AMS_DATA					 109
#define AMS_F_AMS_DATAFINAL				 110
#define AMS_F_AMS_DATAINIT				 111
#define AMS_F_AMS_DECRYPT				 112
#define AMS_F_AMS_DECRYPT_SET1_KEY			 113
#define AMS_F_AMS_DECRYPT_SET1_PASSWORD			 166
#define AMS_F_AMS_DECRYPT_SET1_PKEY			 114
#define AMS_F_AMS_DIGESTALGORITHM_FIND_CTX		 115
#define AMS_F_AMS_DIGESTALGORITHM_INIT_BIO		 116
#define AMS_F_AMS_DIGESTEDDATA_DO_FINAL			 117
#define AMS_F_AMS_DIGEST_VERIFY				 118
#define AMS_F_AMS_ENCODE_RECEIPT			 161
#define AMS_F_AMS_ENCRYPT				 119
#define AMS_F_AMS_ENCRYPTEDCONTENT_INIT_BIO		 120
#define AMS_F_AMS_ENCRYPTEDDATA_DECRYPT			 121
#define AMS_F_AMS_ENCRYPTEDDATA_ENCRYPT			 122
#define AMS_F_AMS_ENCRYPTEDDATA_SET1_KEY		 123
#define AMS_F_AMS_ENVELOPEDDATA_CREATE			 124
#define AMS_F_AMS_ENVELOPEDDATA_INIT_BIO		 125
#define AMS_F_AMS_ENVELOPED_DATA_INIT			 126
#define AMS_F_AMS_FINAL					 127
#define AMS_F_AMS_GET0_CERTIFICATE_CHOICES		 128
#define AMS_F_AMS_GET0_CONTENT				 129
#define AMS_F_AMS_GET0_ECONTENT_TYPE			 130
#define AMS_F_AMS_GET0_ENVELOPED			 131
#define AMS_F_AMS_GET0_REVOCATION_CHOICES		 132
#define AMS_F_AMS_GET0_SIGNED				 133
#define AMS_F_AMS_MSGSIGDIGEST_ADD1			 162
#define AMS_F_AMS_RECEIPTREQUEST_CREATE0		 159
#define AMS_F_AMS_RECEIPT_VERIFY			 160
#define AMS_F_AMS_RECIPIENTINFO_DECRYPT			 134
#define AMS_F_AMS_RECIPIENTINFO_KEKRI_DECRYPT		 135
#define AMS_F_AMS_RECIPIENTINFO_KEKRI_ENCRYPT		 136
#define AMS_F_AMS_RECIPIENTINFO_KEKRI_GET0_ID		 137
#define AMS_F_AMS_RECIPIENTINFO_KEKRI_ID_CMP		 138
#define AMS_F_AMS_RECIPIENTINFO_KTRI_CERT_CMP		 139
#define AMS_F_AMS_RECIPIENTINFO_KTRI_DECRYPT		 140
#define AMS_F_AMS_RECIPIENTINFO_KTRI_ENCRYPT		 141
#define AMS_F_AMS_RECIPIENTINFO_KTRI_GET0_ALGS		 142
#define AMS_F_AMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID	 143
#define AMS_F_AMS_RECIPIENTINFO_PWRI_CRYPT		 167
#define AMS_F_AMS_RECIPIENTINFO_SET0_KEY		 144
#define AMS_F_AMS_RECIPIENTINFO_SET0_PASSWORD		 168
#define AMS_F_AMS_RECIPIENTINFO_SET0_PKEY		 145
#define AMS_F_AMS_SET1_SIGNERIDENTIFIER			 146
#define AMS_F_AMS_SET_DETACHED				 147
#define AMS_F_AMS_SIGN					 148
#define AMS_F_AMS_SIGNED_DATA_INIT			 149
#define AMS_F_AMS_SIGNERINFO_CONTENT_SIGN		 150
#define AMS_F_AMS_SIGNERINFO_SIGN			 151
#define AMS_F_AMS_SIGNERINFO_VERIFY			 152
#define AMS_F_AMS_SIGNERINFO_VERIFY_CERT		 153
#define AMS_F_AMS_SIGNERINFO_VERIFY_CONTENT		 154
#define AMS_F_AMS_SIGN_RECEIPT				 163
#define AMS_F_AMS_STREAM				 155
#define AMS_F_AMS_UNCOMPRESS				 156
#define AMS_F_AMS_VERIFY				 157

/* Reason codes. */
#define AMS_R_ADD_SIGNER_ERROR				 99
#define AMS_R_CERTIFICATE_ALREADY_PRESENT		 175
#define AMS_R_CERTIFICATE_HAS_NO_KEYID			 160
#define AMS_R_CERTIFICATE_VERIFY_ERROR			 100
#define AMS_R_CIPHER_INITIALISATION_ERROR		 101
#define AMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR	 102
#define AMS_R_AMS_DATAFINAL_ERROR			 103
#define AMS_R_AMS_LIB					 104
#define AMS_R_CONTENTIDENTIFIER_MISMATCH		 170
#define AMS_R_CONTENT_NOT_FOUND				 105
#define AMS_R_CONTENT_TYPE_MISMATCH			 171
#define AMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA		 106
#define AMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA		 107
#define AMS_R_CONTENT_TYPE_NOT_SIGNED_DATA		 108
#define AMS_R_CONTENT_VERIFY_ERROR			 109
#define AMS_R_CTRL_ERROR				 110
#define AMS_R_CTRL_FAILURE				 111
#define AMS_R_DECRYPT_ERROR				 112
#define AMS_R_DIGEST_ERROR				 161
#define AMS_R_ERROR_GETTING_PUBLIC_KEY			 113
#define AMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE	 114
#define AMS_R_ERROR_SETTING_KEY				 115
#define AMS_R_ERROR_SETTING_RECIPIENTINFO		 116
#define AMS_R_INVALID_ENCRYPTED_KEY_LENGTH		 117
#define AMS_R_INVALID_KEY_ENCRYPTION_PARAMETER		 176
#define AMS_R_INVALID_KEY_LENGTH			 118
#define AMS_R_MD_BIO_INIT_ERROR				 119
#define AMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH	 120
#define AMS_R_MESSAGEDIGEST_WRONG_LENGTH		 121
#define AMS_R_MSGSIGDIGEST_ERROR			 172
#define AMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE		 162
#define AMS_R_MSGSIGDIGEST_WRONG_LENGTH			 163
#define AMS_R_NEED_ONE_SIGNER				 164
#define AMS_R_NOT_A_SIGNED_RECEIPT			 165
#define AMS_R_NOT_ENCRYPTED_DATA			 122
#define AMS_R_NOT_KEK					 123
#define AMS_R_NOT_KEY_TRANSPORT				 124
#define AMS_R_NOT_PWRI					 177
#define AMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE		 125
#define AMS_R_NO_CIPHER					 126
#define AMS_R_NO_CONTENT				 127
#define AMS_R_NO_CONTENT_TYPE				 173
#define AMS_R_NO_DEFAULT_DIGEST				 128
#define AMS_R_NO_DIGEST_SET				 129
#define AMS_R_NO_KEY					 130
#define AMS_R_NO_KEY_OR_CERT				 174
#define AMS_R_NO_MATCHING_DIGEST			 131
#define AMS_R_NO_MATCHING_RECIPIENT			 132
#define AMS_R_NO_MATCHING_SIGNATURE			 166
#define AMS_R_NO_MSGSIGDIGEST				 167
#define AMS_R_NO_PASSWORD				 178
#define AMS_R_NO_PRIVATE_KEY				 133
#define AMS_R_NO_PUBLIC_KEY				 134
#define AMS_R_NO_RECEIPT_REQUEST			 168
#define AMS_R_NO_SIGNERS				 135
#define AMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE	 136
#define AMS_R_RECEIPT_DECODE_ERROR			 169
#define AMS_R_RECIPIENT_ERROR				 137
#define AMS_R_SIGNER_CERTIFICATE_NOT_FOUND		 138
#define AMS_R_SIGNFINAL_ERROR				 139
#define AMS_R_SMIME_TEXT_ERROR				 140
#define AMS_R_STORE_INIT_ERROR				 141
#define AMS_R_TYPE_NOT_COMPRESSED_DATA			 142
#define AMS_R_TYPE_NOT_DATA				 143
#define AMS_R_TYPE_NOT_DIGESTED_DATA			 144
#define AMS_R_TYPE_NOT_ENCRYPTED_DATA			 145
#define AMS_R_TYPE_NOT_ENVELOPED_DATA			 146
#define AMS_R_UNABLE_TO_FINALIZE_CONTEXT		 147
#define AMS_R_UNKNOWN_CIPHER				 148
#define AMS_R_UNKNOWN_DIGEST_ALGORIHM			 149
#define AMS_R_UNKNOWN_ID				 150
#define AMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM		 151
#define AMS_R_UNSUPPORTED_CONTENT_TYPE			 152
#define AMS_R_UNSUPPORTED_KEK_ALGORITHM			 153
#define AMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM	 179
#define AMS_R_UNSUPPORTED_RECIPIENT_TYPE		 154
#define AMS_R_UNSUPPORTED_RECPIENTINFO_TYPE		 155
#define AMS_R_UNSUPPORTED_TYPE				 156
#define AMS_R_UNWRAP_ERROR				 157
#define AMS_R_UNWRAP_FAILURE				 180
#define AMS_R_VERIFICATION_FAILURE			 158
#define AMS_R_WRAP_ERROR				 159

#ifdef  __cplusplus
}
#endif
#endif
