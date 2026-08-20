/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2022, 2025 IBM Corporation
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef X509_H
#define X509_H

#include <grub/crypto.h>
#include <libtasn1.h>

#include "pk.h"

/* Certificate fingerprint. */
#define GRUB_MAX_FINGERPRINT     3
#define GRUB_FINGERPRINT_SHA256  0
#define GRUB_FINGERPRINT_SHA384  1
#define GRUB_FINGERPRINT_SHA512  2

/* SHA256, SHA384 and SHA512 hash sizes. */
#define SHA256_HASH_SIZE         32
#define SHA384_HASH_SIZE         48
#define SHA512_HASH_SIZE         64

/* Public Key Algorithm. */
struct pk_algo
{
  const char *name;
  const char *aliases;
  const char *oid;
  const grub_int32_t oid_len;
  const grub_pk_verify_t verify;
};
typedef struct pk_algo grub_x509_algo_t;

typedef struct pub_key grub_x509_pk_t;

/* Subject Public Key Info. */
struct spk_info
{
  grub_x509_algo_t pk_algo;
  grub_x509_pk_t pk;
  grub_int32_t pk_len;
};
typedef struct spk_info grub_x509_spki_t;

struct validity
{
  grub_int64_t before;
  grub_int64_t after;
};
typedef struct validity grub_x509_validity_t;

/*
 * One or more x509 certificates. We do limited parsing:
 * extracting only the version, serial, issuer, subject, RSA public key
 * and key size.
 * Also, hold the sha256, sha384, and sha512 fingerprint of the certificate.
 */
struct x509_cert
{
  grub_uint8_t version;
  grub_uint8_t *serial;
  grub_int32_t serial_len;
  char *issuer;
  grub_int32_t issuer_len;
  grub_x509_validity_t validity;
  char *subject;
  grub_int32_t subject_len;
  grub_x509_spki_t spki;
  grub_uint8_t *fingerprint[GRUB_MAX_FINGERPRINT];
  struct x509_cert *next;
};
typedef struct x509_cert grub_x509_cert_t;

/* Type for the x509_fp_cmp function.  */
typedef bool (*grub_x509_fp_cmp_t) (const grub_uint8_t *hash_data,
                                    const grub_size_t hash_data_size,
                                    const grub_x509_cert_t *cert);

/* Type for the x509_cert_cmp function.  */
typedef bool (*grub_x509_cert_cmp_t) (const grub_x509_cert_t *cert1,
                                      const grub_x509_cert_t *cert2);

/* Type for the x509_cert_print function.  */
typedef void (*grub_x509_print_t) (const grub_x509_cert_t *crt);

/* Type for the x509_cert_parse_der function.  */
typedef grub_err_t (*grub_x509_parse_t) (const void *der_data,
                                         const grub_int32_t der_data_len,
                                         grub_x509_cert_t *cert);

/* Type for the x509_cert_release function.  */
typedef void (*grub_x509_release_t) (grub_x509_cert_t *cert);

/* Type for the x509_cert_free function.  */
typedef void (*grub_x509_free_t) (grub_x509_cert_t *cert);

typedef struct x509_spec
{
  const char *name;
  grub_x509_fp_cmp_t fp_cmp;
  grub_x509_cert_cmp_t cert_cmp;
  grub_x509_print_t print;
  grub_x509_parse_t parse_der;
  grub_x509_release_t release;
  grub_x509_free_t free;
} grub_x509_spec_t;

extern grub_x509_spec_t *grub_x509_spec;

#endif /* X509_H */
