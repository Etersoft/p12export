/*
 * Copyright (c) 2019 Dmitry Timoshkov for Etersoft
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <snmp.h>
#include <cryptuiapi.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <applink.c> /* to avoid 'OPENSSL_Uplink: no OPENSSL_Applink' error */

#include "engine/gost_lcl.h"
#include "engine/gosthash2012.h"
#include "engine/gost89.h"
#include "engine/gost_keywrap.h"
#include "gost_asn1_pro.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/* GOST engine */
void ENGINE_load_gost(void);

/* CryptoPro specific typedefs start */
#define GR3410_1_MAGIC           0x3147414d /* MAG1 */
#define CALG_GR3410EL            0x2e23
#define CALG_GR3410_12_256       0x2e49
#define CALG_PRO_EXPORT          0x661f
#define CALG_PRO12_EXPORT        0x6621
#define CALG_SIMPLE_EXPORT       0x6620
#define CALG_DH_EL_SF            0xaa24
#define CALG_DH_EL_EPHEM         0xaa25
#define CALG_DH_GR3410_12_256_EPHEM 0xaa47
#define CALG_DH_GR3410_12_256_SF 0xaa46
#define CALG_DH_GR3410_12_512_SF 0xaa42

typedef struct
{
    DWORD Magic;
    DWORD BitLen;
} CRYPT_PUBKEYPARAM;

typedef struct
{
    BLOBHEADER BlobHeader;
    CRYPT_PUBKEYPARAM KeyParam;
} CRYPT_PUBKEY_INFO_HEADER;

typedef struct
{
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE bASN1GostR3410_2001_PublicKeyParameters[1];
    BYTE bPublicKey[1];
} CRYPT_PUBLICKEYBLOB;

typedef struct
{
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE bExportedKeys[1];
} CRYPT_PRIVATEKEYBLOB;

typedef struct
{
    BLOBHEADER BlobHeader;
    DWORD Magic;
    ALG_ID EncryptKeyAlgId;
} CRYPT_SIMPLEBLOB_HEADER;

typedef struct
{
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    BYTE bSV[8];
    BYTE bEncryptedKey[32];
    BYTE bMacKey[4];
    BYTE bEncryptionParamSet[1];
} CRYPT_SIMPLEBLOB;

typedef struct
{
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    BYTE bSV[8];
    BYTE bEncryptedKey[64];
    BYTE bMacKey[4];
    BYTE bEncryptionParamSet[1];
} CRYPT_SIMPLEBLOB_512;

/* CryptoPro specific typedefs end */

static int debug = 0;

static void print_data(const char *comment, const unsigned char *data, unsigned int length);

static void dprintf(const char *fmt, ...)
{
    if (debug)
    {
        va_list args;

        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}

#define ok(a, b) ok_(__LINE__, (a), (b))
static void ok_(int line, int condition, const char *msg)
{
    if (!condition)
    {
        printf("line %d: %s, error %#08x (%u)\n", line, msg, GetLastError(), GetLastError());
        exit(-1);
    }
}

#define ok_ssl(a, b) ok_ssl_(__LINE__, (a), (b))
static void ok_ssl_(int line, int condition, const char *msg)
{
    if (!condition)
    {
        printf("line %d: %s (%s)\n", line, msg, ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }
}

static const char *propid_to_name(DWORD propid)
{
#define name(id) if (propid == id##_PROP_ID) return #id##"_PROP_ID"

    name(CERT_KEY_PROV_HANDLE);
    name(CERT_KEY_PROV_INFO);
    name(CERT_SHA1_HASH);
    name(CERT_MD5_HASH);
    name(CERT_KEY_CONTEXT);
    name(CERT_KEY_SPEC);
    name(CERT_IE30_RESERVED);
    name(CERT_PUBKEY_HASH_RESERVED);
    name(CERT_ENHKEY_USAGE);
    name(CERT_NEXT_UPDATE_LOCATION);
    name(CERT_FRIENDLY_NAME);
    name(CERT_PVK_FILE);
    name(CERT_DESCRIPTION);
    name(CERT_ACCESS_STATE);
    name(CERT_SIGNATURE_HASH);
    name(CERT_SMART_CARD_DATA);
    name(CERT_EFS);
    name(CERT_FORTEZZA_DATA);
    name(CERT_ARCHIVED);
    name(CERT_KEY_IDENTIFIER);
    name(CERT_AUTO_ENROLL);
    name(CERT_PUBKEY_ALG_PARA);
    name(CERT_CROSS_CERT_DIST_POINTS);
    name(CERT_ISSUER_PUBLIC_KEY_MD5_HASH);
    name(CERT_SUBJECT_PUBLIC_KEY_MD5_HASH);
    name(CERT_ENROLLMENT);
    name(CERT_DATE_STAMP);
    name(CERT_ISSUER_SERIAL_NUMBER_MD5_HASH);
    name(CERT_SUBJECT_NAME_MD5_HASH);
    name(CERT_EXTENDED_ERROR_INFO);
    name(CERT_RENEWAL);
    name(CERT_ARCHIVED_KEY_HASH);
    name(CERT_AUTO_ENROLL_RETRY);
    name(CERT_AIA_URL_RETRIEVED);
    name(CERT_AUTHORITY_INFO_ACCESS);
    name(CERT_BACKED_UP);
    name(CERT_OCSP_RESPONSE);
    name(CERT_REQUEST_ORIGINATOR);
    name(CERT_SOURCE_LOCATION);
    name(CERT_SOURCE_URL);
    name(CERT_NEW_KEY);
    name(CERT_OCSP_CACHE_PREFIX);
    name(CERT_SMART_CARD_ROOT_INFO);
    name(CERT_NO_AUTO_EXPIRE_CHECK);
    name(CERT_NCRYPT_KEY_HANDLE);
    name(CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE);
    name(CERT_SUBJECT_INFO_ACCESS);
    name(CERT_CA_OCSP_AUTHORITY_INFO_ACCESS);
    name(CERT_CA_DISABLE_CRL);
    name(CERT_ROOT_PROGRAM_CERT_POLICIES);
    name(CERT_ROOT_PROGRAM_NAME_CONSTRAINTS);
#undef name

    return "unknown";
}

static void print_cert_info(PCCERT_CONTEXT ctx)
{
    const CERT_PUBLIC_KEY_INFO *info = &ctx->pCertInfo->SubjectPublicKeyInfo;
    char buf[512];
    SYSTEMTIME st;
    DWORD propid, size;

    if (!CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, NULL, buf, sizeof(buf)))
    {
        ok(0, "CertGetNameString");
        return;
    }
    printf("Subject: \"%s\"\n", buf);

    if (!CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            CERT_NAME_ISSUER_FLAG, NULL, buf, sizeof(buf)))
    {
        ok(0, "CertGetNameString");
        return;
    }
    printf("Issuer: \"%s\"\n", buf);

    FileTimeToSystemTime(&ctx->pCertInfo->NotBefore, &st);
    printf("Not valid before: %u.%02u.%04u %02u:%02u:%02u\n",
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

    FileTimeToSystemTime(&ctx->pCertInfo->NotAfter, &st);
    printf("Not valid after: %u.%02u.%04u %02u:%02u:%02u\n",
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

    propid = 0;
    for (;;)
    {
        propid = CertEnumCertificateContextProperties(ctx, propid);
        if (!propid) break;
        if (!CertGetCertificateContextProperty(ctx, propid, NULL, &size))
        {
            ok(0, "CertGetCertificateContextProperty");
            return;
        }
        dprintf("propid: %u (%s), size %u bytes\n", propid, propid_to_name(propid), size);

        if (propid == CERT_KEY_PROV_INFO_PROP_ID)
        {
            CRYPT_KEY_PROV_INFO *key_prov_info;

            key_prov_info = malloc(size);
            CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, key_prov_info, &size);
            dprintf("CERT_KEY_PROV_INFO_PROP_ID: %ws, %ws, type %u, flags %#x, params: %u,%p, keyspec %#x\n",
                  key_prov_info->pwszContainerName, key_prov_info->pwszProvName, key_prov_info->dwProvType,
                  key_prov_info->dwFlags, key_prov_info->cProvParam, key_prov_info->rgProvParam, key_prov_info->dwKeySpec);
            free(key_prov_info);
        }
    }

    dprintf("SubjectPublicKeyInfo.Algorithm.pszObjId %s\n", info->Algorithm.pszObjId);
    dprintf("PublicKey size %lu bytes:\n", info->PublicKey.cbData);
    print_data(NULL, info->PublicKey.pbData, info->PublicKey.cbData);
    dprintf("SignatureAlgorithm.pszObjId %s\n", ctx->pCertInfo->SignatureAlgorithm.pszObjId);
}

static void dump(const char *name, void *data, DWORD size)
{
    FILE *f;

    if (!debug) return;

    printf("saving %s\n", name);

    f = fopen(name, "wb");
    if (f)
    {
        if (data && size)
            fwrite(data, size, 1, f);
        fclose(f);
    }
}

static void print_data(const char *comment, const unsigned char *data, unsigned int length)
{
    unsigned int i;

    if (!debug) return;

    if (comment) printf("%s:", comment);

    for (i = 0; i < length; i++)
    {
        if (i && !(i % 32)) printf("\n");
        printf(" %02x", data[i]);
    }

    printf("\n");
}

static void print_bn(const char *comment, const BIGNUM *bn)
{
    unsigned char buf[64];

    if (!debug) return;

    BN_bn2bin(bn, buf);
    BUF_reverse(buf, NULL, BN_num_bytes(bn));
    print_data(comment, buf, BN_num_bytes(bn));
}

static void print_pubkey_blob(CRYPT_PUBLICKEYBLOB *blob, DWORD size)
{
    DWORD pubkey_size;
    BYTE *key_data;

    if (!debug) return;

    printf("PUBLICKEYBLOB: bType %u, bVersion %u, reserved %u, aiKeyAlg %04x\n",
        blob->tPublicKeyParam.BlobHeader.bType,
        blob->tPublicKeyParam.BlobHeader.bVersion,
        blob->tPublicKeyParam.BlobHeader.reserved,
        blob->tPublicKeyParam.BlobHeader.aiKeyAlg);

    printf("Magic %08x (%4.4s), BitLen %u\n", blob->tPublicKeyParam.KeyParam.Magic,
        (char *)&blob->tPublicKeyParam.KeyParam.Magic, blob->tPublicKeyParam.KeyParam.BitLen);

    pubkey_size = blob->tPublicKeyParam.KeyParam.BitLen / 8;
    printf("bPublicKey size %u bytes\n", pubkey_size);

    key_data = (BYTE *)blob + (size - pubkey_size);
    print_data(NULL, key_data, pubkey_size);
}

static int key_unwrap_2012(EC_KEY *peer_key, EC_KEY *decrypt_key,
                           const unsigned char *wrapped_key,
                           unsigned char *key, int key_len)
{
    static const unsigned char label[] = { 0x26,0xbd,0xb8,0x78 }; /* &Sex ???? */
    unsigned char kek[32], kek_ukm[32], cek_mac[4];
    gost_ctx ctx;

    if (!VKO_compute_key(kek, EC_KEY_get0_public_key(peer_key),
                         decrypt_key, wrapped_key, 8, NID_id_GostR3411_2012_256))
        ok_ssl(0, "VKO_compute_key");

    gost_init(&ctx, &Gost28147_TC26ParamSetZ);
    gost_kdftree2012_256(kek_ukm, 32, kek, 32, label, 4, wrapped_key, 8, 1);

    gost_key(&ctx, kek_ukm);
    gost_dec(&ctx, wrapped_key + 8, key, key_len / 8);
    gost_mac_iv(&ctx, 32, wrapped_key, key, key_len, cek_mac);

    return memcmp(cek_mac, wrapped_key + 8 + key_len, 4) == 0;
}

static int key_unwrap_2001(EC_KEY *peer_key, EC_KEY *decrypt_key,
                           const unsigned char *wrapped_key,
                           unsigned char *key)
{
    unsigned char kek[32], kek_ukm[32], cek_mac[4];
    gost_ctx ctx;

    if (!VKO_compute_key(kek, EC_KEY_get0_public_key(peer_key),
                         decrypt_key, wrapped_key, 8, NID_id_GostR3411_94))
        ok_ssl(0, "VKO_compute_key");

    gost_init(&ctx, &Gost28147_CryptoProParamSetA);
    keyDiversifyCryptoPro(&ctx, kek, wrapped_key, kek_ukm);

    gost_key(&ctx, kek_ukm);
    gost_dec(&ctx, wrapped_key + 8, key, 4);
    gost_mac_iv(&ctx, 32, wrapped_key, key, 32, cek_mac);

    return memcmp(cek_mac, wrapped_key + 8 + 32, 4) == 0;
}

static int decrypt_privatekey_blob(CRYPT_PRIVATEKEYBLOB *blob, DWORD blob_size,
                                   EC_KEY *peer_key, EC_KEY *decrypt_key,
                                   DWORD export_alg, BYTE unwrapped_key[64], DWORD *key_len)
{
    DWORD privatekey_size;
    BYTE wrapped_key[8 + 64 + 4];
    GOST_KEY_TRANSPORT_PRO *gkt;
    const unsigned char *p;

    dprintf("PRIVATEKEYBLOB: bType %u, bVersion %u, reserved %u, aiKeyAlg %04x\n",
        blob->tPublicKeyParam.BlobHeader.bType,
        blob->tPublicKeyParam.BlobHeader.bVersion,
        blob->tPublicKeyParam.BlobHeader.reserved,
        blob->tPublicKeyParam.BlobHeader.aiKeyAlg);

    dprintf("Magic %08x (%4.4s), BitLen %u\n", blob->tPublicKeyParam.KeyParam.Magic,
        &blob->tPublicKeyParam.KeyParam.Magic, blob->tPublicKeyParam.KeyParam.BitLen);

    privatekey_size = blob_size - sizeof(blob->tPublicKeyParam);
    dprintf("bExportedKeys size %u bytes\n", privatekey_size);
    if (!privatekey_size) return 0;
#if 0
if (blob->tPublicKeyParam.KeyParam.BitLen == 32)
    dump("private_PRO12_256.key", blob->bExportedKeys, privatekey_size);
else
    dump("private_PRO12_512.key", blob->bExportedKeys, privatekey_size);
#endif

    dprintf("Parsing %ld bytes...\n", privatekey_size);

    p = blob->bExportedKeys;
    gkt = d2i_GOST_KEY_TRANSPORT_PRO(NULL, (const unsigned char **)&p, privatekey_size);
    ok_ssl(gkt != NULL, "d2i_GOST_KEY_TRANSPORT_PRO");

    if (gkt->imit->length != 4) return 0;
    if (gkt->info->ukm->length != 8) return 0;
    if (gkt->info->key_info->encrypted_key->length != 32 && gkt->info->key_info->encrypted_key->length != 64)
        return 0;
    if (gkt->info->key_info->imit->length != 4) return 0;

    print_data("ukm", gkt->info->ukm->data, 8);
    print_data("key", gkt->info->key_info->encrypted_key->data, gkt->info->key_info->encrypted_key->length);
    print_data("mac", gkt->info->key_info->imit->data, 4);

    memcpy(wrapped_key, gkt->info->ukm->data, 8);
    memcpy(wrapped_key + 8, gkt->info->key_info->encrypted_key->data, gkt->info->key_info->encrypted_key->length);
    memcpy(wrapped_key + 8 + gkt->info->key_info->encrypted_key->length, gkt->info->key_info->imit->data, 4);

    *key_len = blob->tPublicKeyParam.KeyParam.BitLen;

    if (export_alg == CALG_PRO_EXPORT)
    {
        switch (blob->tPublicKeyParam.KeyParam.BitLen)
        {
        case 32:
            if (!key_unwrap_2001(peer_key, decrypt_key, wrapped_key, unwrapped_key))
            {
                dprintf("key_unwrap failed\n");
                return 0;
            }
            break;

        default:
            dprintf("Not supported key length: %u\n", blob->tPublicKeyParam.KeyParam.BitLen);
            return 0;
        }
    }
    else /* CALG_PRO12_EXPORT */
    {
        switch (blob->tPublicKeyParam.KeyParam.BitLen)
        {
        case 32:
        case 64:
            if (!key_unwrap_2012(peer_key, decrypt_key, wrapped_key, unwrapped_key, blob->tPublicKeyParam.KeyParam.BitLen))
            {
                dprintf("key_unwrap failed\n");
                return 0;
            }
            break;

        default:
            dprintf("Not supported key length: %u\n", blob->tPublicKeyParam.KeyParam.BitLen);
            return 0;
        }
    }

    print_data("unwrapped_key", unwrapped_key, blob->tPublicKeyParam.KeyParam.BitLen);
    return 1;
}

static CRYPT_PUBLICKEYBLOB *create_pubkey_blob(EC_KEY *key, DWORD *size, DWORD export_algid)
{
    static const BYTE params_2001[] = {0x30,0x12,0x06,0x07,0x2A,0x85,0x03,0x02,0x02,0x24,0x00,0x06,0x07,0x2A,0x85,0x03,0x02,0x02,0x1E,0x01};
    static const BYTE params_2012[] = {0x30,0x13,0x06,0x07,0x2A,0x85,0x03,0x02,0x02,0x24,0x00,0x06,0x08,0x2A,0x85,0x03,0x07,0x01,0x01,0x02,0x02};
    const BYTE *params;
    DWORD params_len, key_alg;
    CRYPT_PUBLICKEYBLOB *blob;
    BYTE *key_data;
    BIGNUM *x, *y;
    BN_CTX *ctx;

    if (export_algid == CALG_PRO_EXPORT)
    {
        key_alg = CALG_GR3410EL;
        params = params_2001;
        params_len = sizeof(params_2001);
    }
    else /* CALG_PRO12_EXPORT */
    {
        key_alg = CALG_GR3410_12_256;
        params = params_2012;
        params_len = sizeof(params_2012);
    }

    /* get public key and copy it to the blob */
    ctx = BN_CTX_new();
    if (!ctx) return NULL;

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (!x || !y) return NULL;

    if (!EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, ctx))
        ok_ssl(0, "EC_POINT_get_affine_coordinates");

    if (BN_num_bytes(x) > 32)
    {
        dprintf("Not supported public X length: %u bytes\n", BN_num_bytes(x));
        return NULL;
    }
    if (BN_num_bytes(y) > 32)
    {
        dprintf("Not supported public Y length: %u bytes\n", BN_num_bytes(y));
        return NULL;
    }

    *size = sizeof(blob->tPublicKeyParam) + params_len + 64;
    blob = malloc(*size);
    if (!blob) return NULL;

    blob->tPublicKeyParam.BlobHeader.bType = PUBLICKEYBLOB;
    blob->tPublicKeyParam.BlobHeader.bVersion = 0x20;
    blob->tPublicKeyParam.BlobHeader.reserved = 0;
    blob->tPublicKeyParam.BlobHeader.aiKeyAlg = key_alg;
    blob->tPublicKeyParam.KeyParam.Magic = GR3410_1_MAGIC;
    blob->tPublicKeyParam.KeyParam.BitLen = 512;

    memcpy((BYTE *)blob + sizeof(blob->tPublicKeyParam), params, params_len);

    key_data = (BYTE *)blob + sizeof(blob->tPublicKeyParam) + params_len;

    store_bignum(x, key_data + 32, 32);
    store_bignum(y, key_data, 32);
    BUF_reverse(key_data, NULL, 64);

    return blob;
}

static EC_KEY *create_key_pair(void)
{
    EC_KEY *key;
    int ret;

    key = EC_KEY_new();
    ok_ssl(key != NULL, "EC_KEY_new");

    if (!fill_GOST_EC_params(key, NID_id_GostR3410_2001_CryptoPro_A_ParamSet))
        ok_ssl(0, "fill_GOST_EC_params");

    ret = EC_KEY_generate_key(key);
    ok_ssl(ret > 0, "EC_KEY_generate_key");

    return key;
}

static EC_KEY *create_peer_key(CRYPT_PUBLICKEYBLOB *blob, DWORD size)
{
    EC_KEY *key;
    BYTE buf[32], *key_data;
    BIGNUM *x, *y;

    ok(blob->tPublicKeyParam.KeyParam.BitLen == 512, "Not supported KeyParam.BitLen\n");

    key = EC_KEY_new();
    ok_ssl(key != NULL, "EC_KEY_new");

    if (!fill_GOST_EC_params(key, NID_id_GostR3410_2001_CryptoPro_A_ParamSet))
        ok_ssl(0, "fill_GOST_EC_params");

    key_data = (BYTE *)blob + (size - blob->tPublicKeyParam.KeyParam.BitLen / 8);

    memcpy(buf, key_data, 32);
    BUF_reverse(buf, NULL, 32);
    x = BN_bin2bn(buf, 32, NULL);
    ok_ssl(x != NULL, "BN_bin2bn");

    memcpy(buf, key_data + 32, 32);
    BUF_reverse(buf, NULL, 32);
    y = BN_bin2bn(buf, 32, NULL);
    ok_ssl(y != NULL, "BN_bin2bn");

    if (!EC_KEY_set_public_key_affine_coordinates(key, x, y))
        ok_ssl(0, "EC_KEY_set_public_key_affine_coordinates");

    return key;
}

static HCRYPTKEY create_export_key(HCRYPTPROV hprov, EC_KEY **peer_key, EC_KEY **decrypt_key,
                                   DWORD export_algid)
{
    HCRYPTKEY hkey_ephem, hkey_export;
    CRYPT_PUBLICKEYBLOB *blob;
    DWORD size;
    BOOL ret;

    if (export_algid == CALG_PRO_EXPORT)
        ret = CryptGenKey(hprov, CALG_DH_EL_EPHEM, 0, &hkey_ephem);
    else /* CALG_PRO12_EXPORT */
        ret = CryptGenKey(hprov, CALG_DH_GR3410_12_256_EPHEM, 0, &hkey_ephem);
    ok(ret, "CryptGenKey");

    ret = CryptExportKey(hkey_ephem, 0, PUBLICKEYBLOB, 0, NULL, &size);
    ok(ret, "CryptExportKey");
    dprintf("PUBLICKEYBLOB size %u bytes\n", size);

    blob = malloc(size);
    ret = CryptExportKey(hkey_ephem, 0, PUBLICKEYBLOB, 0, (BYTE *)blob, &size);
    ok(ret, "CryptExportKey");

//    dump("private_pub1.key", blob, size);
    print_pubkey_blob(blob, size);

    *peer_key = create_peer_key(blob, size);
    ok_ssl(*peer_key != 0, "create_peer_key");

    free(blob);

    *decrypt_key = create_key_pair();
    ok_ssl(*decrypt_key != 0, "create_key_pair");

    blob = create_pubkey_blob(*decrypt_key, &size, export_algid);
    ok(blob != NULL, "create_pubkey_blob");
    print_pubkey_blob(blob, size);

    ret = CryptImportKey(hprov, (BYTE *)blob, size, hkey_ephem, 0, &hkey_export);
    ok(ret, "CryptImportKey");

    CryptDestroyKey(hkey_ephem);

    free(blob);

    return hkey_export;
}

static void init_gost(void)
{
    ENGINE *gost;

    ENGINE_load_gost();

    gost = ENGINE_by_id("gost");
    if (gost)
    {
        ENGINE_init(gost);
        ENGINE_set_default(gost, ENGINE_METHOD_ALL);
    }
    else
        printf("Warning: GOST engine is not available\n");
}

static X509 *create_x509(PCCERT_CONTEXT cert, int *algo_nid, int *paramset_nid)
{
    X509 *x509;
    X509_PUBKEY *x509_pk;
    X509_ALGOR *x509_alg;
    ASN1_OBJECT *obj;
    ASN1_TYPE *type;
    ASN1_STRING *val;
    STACK_OF(ASN1_TYPE) *seq;
    const unsigned char *p;
    int ret, pptype;

    p = cert->pbCertEncoded;
    x509 = d2i_X509(NULL, &p, cert->cbCertEncoded);
    ok_ssl(x509 != NULL, "d2i_X509");

    x509_pk = X509_get_X509_PUBKEY(x509);
    ret = X509_PUBKEY_get0_param(&obj, NULL, 0, &x509_alg, x509_pk);
    ok_ssl(ret, "X509_PUBKEY_get0_param");
    *algo_nid = OBJ_obj2nid(obj);
    dprintf("certificate public key: %d %s", *algo_nid, OBJ_nid2sn(*algo_nid));

    val = NULL;
    X509_ALGOR_get0(NULL, &pptype, (const void **)&val, x509_alg);
    ok(pptype == V_ASN1_SEQUENCE, "wrong type");

    p = val->data;
    seq = d2i_ASN1_SEQUENCE_ANY(NULL, &p, val->length);
    ok_ssl(seq != NULL, "d2i_ASN1_SEQUENCE_ANY");

    type = sk_ASN1_TYPE_value(seq, 0);
    ok_ssl(type != NULL, "sk_ASN1_TYPE_value");
    *paramset_nid = OBJ_obj2nid((ASN1_OBJECT *)type->value.ptr);
    dprintf(" (%d %s)\n", *paramset_nid, OBJ_nid2sn(*paramset_nid));
    sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);

    return x509;
}

static int X509_check_private_key(const X509 *x, const EVP_PKEY *k)
{
    const EVP_PKEY *xk;
    int ret;

    xk = X509_get0_pubkey(x);

    if (xk)
        ret = EVP_PKEY_cmp(xk, k);
    else
        ret = -2;

    return ret;

#if 0
    switch (ret) {
    case 1:
        break;
    case 0:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_VALUES_MISMATCH);
        break;
    case -1:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_TYPE_MISMATCH);
        break;
    case -2:
        X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_UNKNOWN_KEY_TYPE);
    }
#endif
}

#define MAX_PASSWORD 1024
struct user
{
    char password[MAX_PASSWORD];
    char confirmation[MAX_PASSWORD];
};

#define IDC_PASSWORD 100
#define IDC_CONFIRMATION 101

static INT_PTR CALLBACK password_dlgproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    static struct user *user = NULL;

    switch (msg)
    {
    case WM_INITDIALOG:
        user = (struct user *)lp;
        return TRUE;

    case WM_COMMAND:
        if (wp == IDOK)
        {
            if (!GetDlgItemText(hwnd, IDC_PASSWORD, user->password, MAX_PASSWORD))
                user->password[0] = 0;

            if (!GetDlgItemText(hwnd, IDC_CONFIRMATION, user->confirmation, MAX_PASSWORD))
                user->confirmation[0] = 0;

            if (strcmp(user->password, user->confirmation) != 0)
                MessageBox(0, "Entered passwords don't match, please try again", "Error", MB_OK | MB_ICONHAND);
            else
                EndDialog(hwnd, IDOK);
        }
        else if (wp == IDCANCEL)
        {
            user->password[0] = 0;
            user->confirmation[0] = 0;
            EndDialog(hwnd, IDCANCEL);
        }
        return TRUE;

    default:
        break;
    }

    return FALSE;
}

static void fixup_illegal_chars(WCHAR *name)
{
    static const char illegal[] = "*?<>|\"+=,;[]:/\\\345";

    while (*name)
    {
        if (*name < 0xff && strchr(illegal, *name)) *name = '_';
        name++;
    }
}

static int save_p12(BYTE *unwrapped_key, int key_len, PCCERT_CONTEXT cert)
{
    WCHAR bufW[512];
    BYTE buf[512];
    struct user user;
    X509 *x509;
    BIGNUM *bnkey;
    EC_KEY *eckey;
    EVP_PKEY *pkey;
    FILE *fp;
    PKCS12 *p12;
    int ret;
    int key_nid, paramset_nid;

    user.password[0] = 0;
    ret = DialogBoxParam(GetModuleHandle(NULL), (LPCSTR)1, NULL, password_dlgproc, (LPARAM)&user);
    if (ret != IDOK)
    {
        printf("User aborted the operation\n");
        return 0;
    }

    x509 = create_x509(cert, &key_nid, &paramset_nid);
    ok_ssl(x509 != NULL, "create_x509");

    memcpy(buf, unwrapped_key, key_len);
    BUF_reverse(buf, NULL, key_len);
    bnkey = BN_bin2bn(buf, key_len, NULL);
    ok(bnkey != NULL, "BN_bin2bn");

    eckey = EC_KEY_new();
    ok_ssl(eckey != NULL, "EC_KEY_new");
    if (!fill_GOST_EC_params(eckey, paramset_nid))
    {
        dprintf("OpenSSL doesn't support the key algorithm\n");
        return 0;
    }
    ret = EC_KEY_set_private_key(eckey, bnkey);
    ok_ssl(ret, "EC_KEY_set_private_key");

    gost_ec_compute_public(eckey);

    pkey = EVP_PKEY_new();
    ok_ssl(pkey != NULL, "EVP_PKEY_new");
    ret = EVP_PKEY_assign(pkey, key_nid, eckey);
    ok_ssl(ret > 0, "EVP_PKEY_assign");

    ret = X509_check_private_key(x509, pkey);
    ok_ssl(ret == 1, "X509_check_private_key");

    ret = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, bufW, ARRAY_SIZE(bufW));
    ok(ret, "CertGetNameString");
    WideCharToMultiByte(CP_UTF8, 0, bufW, -1, buf, sizeof(buf), NULL, NULL);

    /* For compatibility we need to use HMACGostR3411_94 */
    gost_set_default_param(GOST_PARAM_PBE_PARAMS, "md_gost94");

    p12 = PKCS12_create(user.password, buf, pkey, x509, NULL,
                        NID_id_Gost28147_89, NID_id_Gost28147_89, 0, -1, 0);
    ok_ssl(p12 != NULL, "PKCS12_create");

    /* For compatibility we need to use GostR3411_94 and 32 bytes of salt */
    ret = PKCS12_set_mac(p12, user.password, -1, NULL, 32, 0, EVP_get_digestbynid(NID_id_GostR3411_94));
    ok_ssl(ret == 1, "PKCS12_set_mac");

    fixup_illegal_chars(bufW);
    WideCharToMultiByte(CP_ACP, 0, bufW, -1, buf, sizeof(buf), NULL, NULL);
    strcat(buf, ".pfx");
    printf("Saving \"%s\"...\n", buf);

    fp = fopen(buf, "wb");
    ok(fp != NULL, "fopen");

    ret = i2d_PKCS12_fp(fp, p12);
    ok_ssl(ret == 1, "i2d_PKCS12_fp");

    PKCS12_free(p12);
    fclose(fp);

    printf("Done.\n");

    if (debug)
    {
        X509 *test_x509;
        EVP_PKEY *test_pkey;

        fp = fopen(buf, "rb");
        ok(fp != NULL, "fopen");

        p12 = NULL;
        p12 = d2i_PKCS12_fp(fp, &p12);
        ok_ssl(p12 != NULL, "d2i_PKCS12_fp");

        ret = PKCS12_parse(p12, user.password, &test_pkey, &test_x509, NULL);
        ok_ssl(ret == 1, "PKCS12_parse");

        ret = X509_check_private_key(test_x509, test_pkey);
        ok_ssl(ret == 1, "X509_check_private_key");

        ret = X509_check_private_key(test_x509, pkey);
        ok_ssl(ret == 1, "X509_check_private_key");

        ret = X509_check_private_key(x509, test_pkey);
        ok_ssl(ret == 1, "X509_check_private_key");

        PKCS12_free(p12);
        fclose(fp);
    }

    return 1;
}

int main(int argc, char *argv[])
{
    HCERTSTORE store;
    PCCERT_CONTEXT cert;
    DWORD keyspec, size, key_alg, key_len, perm;
    HCRYPTPROV hprov;
    HCRYPTKEY hkey_user, hkey_export;
    EC_KEY *peer_key, *decrypt_key;
    void *blob;
    BOOL free_hprov;
    int ret, i;
    BYTE unwrapped_key[64];

    SetConsoleOutputCP(GetACP());

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
            case 'd':
            case 'D':
                debug = 1;
                break;

            default:
                break;
            }
        }
    }

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, "My");
    ok(store != NULL, "CertOpenStore");

    cert = CryptUIDlgSelectCertificateFromStore(store, 0, L"Select certificate for export", NULL, 0, 0, NULL);
    if (!cert) return -1;

    printf("Selected certificate:\n");
    print_cert_info(cert);

    ret = CryptAcquireCertificatePrivateKey(cert, 0, NULL, &hprov, &keyspec, &free_hprov);
    ok(ret, "CryptAcquireCertificatePrivateKey");

    ret = CryptGetUserKey(hprov, keyspec, &hkey_user);
    ok(ret, "CryptGetUserKey");

    size = sizeof(key_alg);
    ret = CryptGetKeyParam(hkey_user, KP_ALGID, (BYTE *)&key_alg, &size, 0);
    ok(ret, "CryptGetKeyParam");
    dprintf("KP_ALGID %04x\n", key_alg);

    size = sizeof(key_len);
    ret = CryptGetKeyParam(hkey_user, KP_KEYLEN, (BYTE *)&key_len, &size, 0);
    ok(ret, "CryptGetKeyParam");
    dprintf("KP_KEYLEN: %u\n", key_len);

    size = sizeof(perm);
    ret = CryptGetKeyParam(hkey_user, KP_PERMISSIONS, (BYTE *)&perm, &size, 0);
    ok(ret, "CryptGetKeyParam");
    dprintf("KP_PERMISSIONS: %#x\n", perm);

    switch (key_alg)
    {
    case CALG_DH_EL_SF:
    case CALG_GR3410EL:
        key_alg = CALG_PRO_EXPORT;
        break;

    case CALG_DH_GR3410_12_256_SF:
    case CALG_DH_GR3410_12_512_SF:
        key_alg = CALG_PRO12_EXPORT;
        break;

    default:
        printf("Not supported key algorithm %#x\n", key_alg);
        return -1;
    }

    init_gost();

    /* PRIVATEKEYBLOB export */
    hkey_export = create_export_key(hprov, &peer_key, &decrypt_key, key_alg);
    if (!hkey_export) return -1;

    ret = CryptSetKeyParam(hkey_export, KP_ALGID, (BYTE *)&key_alg, 0);
    ok(ret, "CryptSetKeyParam");

    ret = CryptExportKey(hkey_user, hkey_export, PRIVATEKEYBLOB, 0, NULL, &size);
    ok(ret, "CryptExportKey");
    dprintf("PRIVATEKEYBLOB size %u bytes\n", size);
    blob = malloc(size);
    ret = CryptExportKey(hkey_user, hkey_export, PRIVATEKEYBLOB, 0, blob, &size);
    ok(ret, "CryptExportKey");

//    dump("private.key", blob, size);
    if (!decrypt_privatekey_blob(blob, size, peer_key, decrypt_key, key_alg, unwrapped_key, &key_len))
        return -1;

    save_p12(unwrapped_key, key_len, cert);

    return 0;
}
