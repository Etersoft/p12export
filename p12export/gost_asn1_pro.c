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

#include <openssl/asn1t.h>
#include <openssl/x509.h>

#include "engine/gost_lcl.h"
#include "gost_asn1_pro.h"

ASN1_NDEF_SEQUENCE(GOST_KEY_TRANSPORT_PRO) =
{
    ASN1_SIMPLE(GOST_KEY_TRANSPORT_PRO, info, GOST_KEY_INFO_PRO),
    ASN1_SIMPLE(GOST_KEY_TRANSPORT_PRO, imit, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_TRANSPORT_PRO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_TRANSPORT_PRO)

ASN1_NDEF_SEQUENCE(GOST_KEY_INFO_PRO) =
{
    ASN1_SIMPLE(GOST_KEY_INFO_PRO, ukm, ASN1_OCTET_STRING),
    ASN1_SIMPLE(GOST_KEY_INFO_PRO, key_info, GOST_KEY_INFO),
    ASN1_IMP(GOST_KEY_INFO_PRO, key_params, GOST_KEY_PARAMS_PRO, 0)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_INFO_PRO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_INFO_PRO)

ASN1_NDEF_SEQUENCE(GOST_KEY_PARAMS_PRO) =
{
    ASN1_SIMPLE(GOST_KEY_PARAMS_PRO, flags, ASN1_BIT_STRING),
    ASN1_IMP(GOST_KEY_PARAMS_PRO, algo_id, GOST_ALGORITHM_IDENTIFIER, 0)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_PARAMS_PRO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_PARAMS_PRO)

ASN1_NDEF_SEQUENCE(GOST_ALGORITHM_IDENTIFIER) =
{
    ASN1_SIMPLE(GOST_ALGORITHM_IDENTIFIER, algorithm, ASN1_OBJECT),
    ASN1_SIMPLE(GOST_ALGORITHM_IDENTIFIER, params, GOST_KEY_PARAMS)
} ASN1_NDEF_SEQUENCE_END(GOST_ALGORITHM_IDENTIFIER)
IMPLEMENT_ASN1_FUNCTIONS(GOST_ALGORITHM_IDENTIFIER)
