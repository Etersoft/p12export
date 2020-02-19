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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#ifdef _WIN32
#include <applink.c> /* to avoid 'OPENSSL_Uplink: no OPENSSL_Applink' error */
#endif

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
void ENGINE_load_gost(void);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **alg,
                                 const ASN1_OCTET_STRING **digest)
{
    *alg = sig->algor;
    *digest = sig->digest;
}

static inline void PKCS12_get0_mac(const ASN1_OCTET_STRING **mac, const X509_ALGOR **algid,
                                   const ASN1_OCTET_STRING **salt, const ASN1_INTEGER **iter,
                                   const PKCS12 *p12)
{
    if (!p12->mac) return;

    X509_SIG_get0(p12->mac->dinfo, algid, mac);
    *salt = p12->mac->salt;
    *iter = p12->mac->iter;
}
#endif

#define ok_ssl(a, b) ok_ssl_(__LINE__, (a), (b))
static void ok_ssl_(int line, int condition, const char *msg)
{
    if (!condition)
    {
        printf("line %d: %s (%s)\n", line, msg, ERR_error_string(ERR_get_error(), NULL));
        exit(-1);
    }
}

static void init_gost(void)
{
    ENGINE *gost;

    ENGINE_load_builtin_engines();

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
    ENGINE_load_gost();
#endif

    gost = ENGINE_by_id("gost");
    if (gost)
    {
        ENGINE_init(gost);
        ENGINE_set_default(gost, ENGINE_METHOD_ALL);
    }
    else
        printf("Warning: GOST engine is not available\n");
}

int main(int argc, char *argv[])
{
    const char *password = "";
    int ret;
    FILE *fp;
    BIO *bio;
    PKCS12 *p12;
    X509 *x509;
    EVP_PKEY *pkey;

    if (argc < 2)
    {
        printf("Syntax: p12info [container] [password]\n");
        return -1;
    }

    init_gost();

    if (argc > 2)
        password = argv[2];

    printf("Container: %s\n", argv[1]);

    fp = fopen(argv[1], "rb");
    if (fp == NULL)
    {
        printf("Failed to open %s\n", argv[1]);
        return -1;
    }

    bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    ok_ssl(bio != NULL, "BIO_new_fp");

    p12 = NULL;
    p12 = d2i_PKCS12_fp(fp, &p12);
    ok_ssl(p12 != NULL, "d2i_PKCS12_fp");

    fclose(fp);

    if (PKCS12_mac_present(p12))
    {
        const ASN1_OCTET_STRING *mac = NULL;
        const ASN1_INTEGER *iter = NULL;
        const ASN1_OCTET_STRING *salt = NULL;
        X509_ALGOR *algid;
        const ASN1_OBJECT *obj;

        PKCS12_get0_mac(&mac, (const X509_ALGOR **)&algid, &salt, &iter, p12);
        X509_ALGOR_get0(&obj, NULL, NULL, algid);
        printf("MAC: algorithm ");
        i2a_ASN1_OBJECT(bio, obj);
        printf(", length: %d, iteration %ld, salt length %d\n",
               mac ? ASN1_STRING_length(mac) : 0,
               iter ? ASN1_INTEGER_get(iter) : 1,
               salt ? ASN1_STRING_length(salt) : 0);
    }

    /* In PKCS#12 no password and a zero length password are different
     * things, fortunately PKCS12_parse tries both variants.
     */
    ret = PKCS12_parse(p12, password, &pkey, &x509, NULL);
    ok_ssl(ret == 1, "PKCS12_parse");

    PKCS12_free(p12);

    ret = X509_check_private_key(x509, pkey);
    ok_ssl(ret == 1, "X509_check_private_key");

    EVP_PKEY_print_private(bio, pkey, 0, NULL);
    X509_print(bio, x509);

    return 0;
}
