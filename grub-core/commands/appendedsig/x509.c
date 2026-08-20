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

#include <libtasn1.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include <grub/gcrypt/gcrypt.h>

#include "util.h"
#include "asn1_util.h"
#include "x509.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

static const char *ca_false_str = "FALSE";
static const grub_int32_t ca_false_str_len = 5;
static const char *critical_true_str = "TRUE";
static const grub_int32_t critical_true_str_len = 4;

/* RFC 5280 Appendix A. */
static const char *commonName_oid = "2.5.4.3";
static const grub_int32_t commonName_oid_len = 7;

/* RFC 5280 4.2.1.3 Key Usage. */
static const char *keyUsage_oid = "2.5.29.15";
static const grub_int32_t keyUsage_oid_len = 9;

static const grub_uint8_t digitalSignatureUsage = 0x80;

/* RFC 5280 4.2.1.9 Basic Constraints. */
static const char *basicConstraints_oid = "2.5.29.19";
static const grub_int32_t basicConstraints_oid_len = 9;

/* RFC 5280 4.2.1.12 Extended Key Usage. */
static const char *extendedKeyUsage_oid = "2.5.29.37";
static const char *codeSigningUsage_oid = "1.3.6.1.5.5.7.3.3";
static const grub_int32_t extendedKeyUsage_oid_len = 9;
static const grub_int32_t codeSigningUsage_oid_len = 17;

/* RFC 3279 2.3.1  RSA Keys and RFC 9881 MLDSA. */
static const grub_x509_algo_t pk_algos[] =
{
  {"rsaEncryption", "rsa", "1.2.840.113549.1.1.1", 20, &grub_pk_rsa_verify},
  {"ML-DSA-44", "dilithium2", "2.16.840.1.101.3.4.3.17", 23, &grub_pk_mldsa_verify},
  {"ML-DSA-65", "dilithium3", "2.16.840.1.101.3.4.3.18", 23, &grub_pk_mldsa_verify},
  {"ML-DSA-87", "dilithium5", "2.16.840.1.101.3.4.3.19", 23, &grub_pk_mldsa_verify}
};

static const grub_int32_t rsa_key[] = {2048, 3072, 4096};
static const grub_int32_t mldsa_key[] = {1312*8, 1952*8, 2592*8};

static bool
x509_is_mldsa_algo (const char *algo_oid, const grub_int32_t algo_oid_len)
{
  grub_size_t i;

  for (i = 1; i < sizeof (pk_algos)/sizeof(pk_algos[0]); i++)
     {
       if (pk_algos[i].oid_len == algo_oid_len &&
           grub_strncmp (algo_oid, pk_algos[i].oid, pk_algos[i].oid_len) == 0)
         return true;
     }

  return false;
}

static bool
x509_is_valid_pkalgo (const char *algo_oid, const grub_int32_t algo_oid_len)
{
  grub_size_t i;

  for (i = 0; i < sizeof (pk_algos)/sizeof(pk_algos[0]); i++)
     {
       if (pk_algos[i].oid_len == algo_oid_len &&
           grub_strncmp (algo_oid, pk_algos[i].oid,  pk_algos[i].oid_len) == 0)
         return true;
     }

  return false;
}

static bool
x509_is_valid_mldsa_key (const grub_int32_t key_size)
{
  grub_size_t i;

  for (i = 0; i < sizeof (mldsa_key)/sizeof(mldsa_key[0]); i++)
     {
       if (key_size == mldsa_key[i])
         return true;
     }

  return false;
}

static bool
x509_is_valid_rsa_key (const grub_int32_t m_size, const grub_int32_t e_size)
{
  grub_size_t i;

  for (i = 0; i < sizeof (rsa_key)/sizeof(rsa_key[0]); i++)
     {
       if (m_size == rsa_key[i] && e_size == 3)
         return true;
     }

  return false;
}

/*
 * RFC 3279 2.3.1
 *
 *  The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey:
 *
 *     RSAPublicKey ::= SEQUENCE {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 *  where modulus is the modulus n, and publicExponent is the public exponent e.
 */
static grub_err_t
x509_get_rsa_pubkey (grub_uint8_t *der_data, grub_int32_t der_data_size, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  gcry_error_t gcry_err;
  grub_err_t err = GRUB_ERR_NONE;
  asn1_node rsa_pk_asn1 = NULL;
  grub_uint8_t *m_data, *e_data;
  grub_int32_t m_size, e_size;

  rc = asn1_create_element (grub_gnutls_gnutls_asn, "GNUTLS.RSAPublicKey", &rsa_pk_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "cannot create storage for public key ASN.1 data");

  rc = asn1_der_decoding2 (&rsa_pk_asn1, der_data, &der_data_size,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "cannot decode certificate public key DER: %s", asn1_error);

  m_data = grub_asn1_allocate_and_read (rsa_pk_asn1, "modulus", "RSA modulus", &m_size);
  if (m_data == NULL)
    {
      err = grub_errno;
      goto exit;
    }

  e_data = grub_asn1_allocate_and_read (rsa_pk_asn1, "publicExponent",
                                        "RSA public exponent", &e_size);
  if (e_data == NULL)
    {
      err = grub_errno;
      goto clean_exit;
    }

  if (x509_is_valid_rsa_key ((m_size * 8) - 8, e_size) == false)
    {
      err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		        "unsupported public key: m-%d e-%d", (m_size * 8) - 8, e_size);
      goto clean_exit;
    }

  /*
   * Convert m, e to mpi
   *
   * nscanned is not set for FMT_USG, it's only set for FMT_PGP, so we can't
   * verify it.
   */
  gcry_err = _gcry_mpi_scan (&cert->spki.pk.modulus, GCRYMPI_FMT_USG,
                             m_data, m_size, NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err =  grub_error (GRUB_ERR_BAD_FILE_TYPE,
                         "error loading RSA modulus into MPI structure: %d", gcry_err);
      goto clean_exit;
    }

  gcry_err = _gcry_mpi_scan (&cert->spki.pk.exponent, GCRYMPI_FMT_USG,
                             e_data, e_size, NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      _gcry_mpi_release (cert->spki.pk.modulus);
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error loading RSA exponent into MPI structure: %d", gcry_err);
    }
  else
    /* RSA key size in bits. */
    cert->spki.pk_len = (m_size * 8) - 8;

 clean_exit:
  grub_free (m_data);
  grub_free (e_data);
 exit:
  asn1_delete_structure (&rsa_pk_asn1);

  return err;
}

/* Verify the Key Usage extension. We require the Digital Signature usage. */
static grub_err_t
x509_verify_key_usage (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node usage_asn = NULL;
  grub_int32_t rc;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t usage = 0xff;
  grub_int32_t usage_size = sizeof (usage_size);

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.KeyUsage", &usage_asn);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for key usage");

  rc = asn1_der_decoding2 (&usage_asn, value, &value_size,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Key Usage: %s", asn1_error);
      goto cleanup;
    }

  rc = asn1_read_value (usage_asn, "", &usage, &usage_size);
  if (rc != ASN1_SUCCESS || usage_size == 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Key Usage value: %s",
                        ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
      goto cleanup;
    }

  if (!(usage & digitalSignatureUsage))
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "key usage (0x%x) missing Digital Signature usage", usage);
      goto cleanup;
    }

 cleanup:
  asn1_delete_structure (&usage_asn);

  return err;
}

/*
 * BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
static grub_err_t
x509_verify_basic_constraints (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node basic_asn = NULL;
  grub_int32_t rc;
  grub_err_t err = GRUB_ERR_NONE;
  char cA[6]; /* FALSE or TRUE. */
  grub_int32_t cA_size = sizeof (cA);

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.BasicConstraints", &basic_asn);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for Basic Constraints");

  rc = asn1_der_decoding2 (&basic_asn, value, &value_size,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Basic Constraints: %s", asn1_error);
      goto cleanup;
    }

  rc = asn1_read_value (basic_asn, "cA", cA, &cA_size);
  if (rc == ASN1_ELEMENT_NOT_FOUND)
    {
      /* Not present, default is False, so this is OK. */
      err = GRUB_ERR_NONE;
      goto cleanup;
    }
  else if (rc != ASN1_SUCCESS || cA_size == 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Basic Constraints cA value: %s",
                        ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
      goto cleanup;
    }

  /* The certificate must not be a CA certificate. */
  if (ca_false_str_len != cA_size - 1 ||
      grub_strncmp (ca_false_str, cA, cA_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "unexpected CA value: %s", cA);
      goto cleanup;
    }

 cleanup:
  asn1_delete_structure (&basic_asn);

  return err;
}

/*
 * Verify the Extended Key Usage extension. We require the Code Signing usage.
 *
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static grub_err_t
x509_verify_extended_key_usage (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node extended_asn = NULL;
  grub_int32_t rc, count, i = 0;
  grub_err_t err = GRUB_ERR_NONE;
  char usage[GRUB_MAX_OID_LEN], name[3];
  grub_int32_t usage_size = sizeof (usage);

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.ExtKeyUsageSyntax", &extended_asn);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for Extended Key Usage");

  rc = asn1_der_decoding2 (&extended_asn, value, &value_size,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Extended Key Usage: %s", asn1_error);
      goto cleanup;
    }

  /* If EKUs are present, it checks the presents of Code Signing usage. */
  rc = asn1_number_of_elements (extended_asn, "", &count);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting number of Extended Key Usages: %s",
                        asn1_strerror (rc));
      goto cleanup;
    }

  for (i = 1; i < count + 1; i++)
    {
      grub_memset (name, 0, sizeof (name));
      grub_snprintf (name, sizeof (name), "?%d", i);
      rc = asn1_read_value (extended_asn, name, usage, &usage_size);
      if (rc != ASN1_SUCCESS || usage_size == 0)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Extended Key Usage: %s",
                            ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
          goto cleanup;
        }

      if (codeSigningUsage_oid_len == usage_size - 1 &&
          grub_strncmp (codeSigningUsage_oid, usage, usage_size) == 0)
        goto cleanup;
    }

  err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "extended key usage missing Code Signing usage");

 cleanup:
  asn1_delete_structure (&extended_asn);

  return err;
}

/*
 * TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 * ...
 *
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static grub_err_t
x509_get_version (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  const char *name = "tbsCertificate.version";
  grub_uint8_t version;
  grub_int32_t version_len = sizeof (version);

  rc = asn1_read_value (cert_asn1, name, &version, &version_len);
  /* Require version 3. */
  if (rc != ASN1_SUCCESS || version_len != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading certificate version");

  if (version != 0x02)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "invalid x509 certificate version, expected v3 (0x02), got 0x%02x.",
                       version);

  cert->version = version;

  return GRUB_ERR_NONE;
}

static grub_err_t
x509_get_serial (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_err_t ret;
  grub_int32_t serial_size;
  grub_uint8_t *serial;

  serial = grub_asn1_allocate_and_read (cert_asn1, "tbsCertificate.serialNumber",
                                        "certificate serial number", &serial_size);
  if (serial == NULL)
    return grub_errno;

  ret = grub_util_buffer2hex (serial, serial_size, &cert->serial,
                              &cert->serial_len);
  grub_free (serial);

  return ret;
}

static grub_err_t
x509_get_validity (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_err_t ret;
  grub_int32_t raw_time_len, type_len;
  char *raw_time, *type, *validity_path;

  type = grub_asn1_allocate_and_read (cert_asn1, "tbsCertificate.validity.notBefore",
                                      "certificate validity notBefore type", &type_len);
  if (type == NULL)
    return grub_errno;

  validity_path = grub_xasprintf ("tbsCertificate.validity.notBefore.%s", type);
  grub_free (type);
  if (validity_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  raw_time = grub_asn1_allocate_and_read (cert_asn1, validity_path,
                                          "certificate validity notBefore", &raw_time_len);
  grub_free (validity_path);
  if (raw_time == NULL)
    return grub_errno;

  ret = grub_asn1_decode_datetime (raw_time, raw_time_len - 1, &cert->validity.before);
  grub_free (raw_time);
  if (ret != GRUB_ERR_NONE)
    return ret;

  type = grub_asn1_allocate_and_read (cert_asn1, "tbsCertificate.validity.notAfter",
                                      "certificate validity notAfter type", &type_len);
  if (type == NULL)
    return grub_errno;

  validity_path = grub_xasprintf ("tbsCertificate.validity.notAfter.%s", type);
  grub_free (type);
  if (validity_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  raw_time = grub_asn1_allocate_and_read (cert_asn1, validity_path,
                                          "certificate validity notAfter", &raw_time_len);
  grub_free (validity_path);
  if (raw_time == NULL)
    return grub_errno;

  ret = grub_asn1_decode_datetime (raw_time, raw_time_len - 1, &cert->validity.after);
  grub_free (raw_time);
  if (ret != GRUB_ERR_NONE)
    return ret;

  return ret;
}

static grub_err_t
x509_get_issuer_and_subject (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_err_t ret;

  ret = grub_asn1_read_rnd_sequence (cert_asn1, "tbsCertificate.issuer", commonName_oid,
                                     commonName_oid_len, &cert->issuer, &cert->issuer_len);
  if (ret != GRUB_ERR_NONE)
    {
      grub_free (cert->serial);
      return ret;
    }

  ret = grub_asn1_read_rnd_sequence (cert_asn1, "tbsCertificate.subject", commonName_oid,
                                     commonName_oid_len, &cert->subject, &cert->subject_len);
  if (ret != GRUB_ERR_NONE)
    {
      grub_free (cert->serial);
      grub_free (cert->issuer);
      return ret;
    }

  return GRUB_ERR_NONE;
}

/*
 * RFC 5280:
 *   SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 * AlgorithmIdentifiers come from RFC 3279, we are not strictly compilant as we
 * only support RSA Encryption.
 */
static grub_err_t
x509_get_subject_public_key (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  grub_err_t ret = GRUB_ERR_NONE;
  const char *algo_name = "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm";
  const char *params_name = "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters";
  const char *pk_name = "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey";
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_size = sizeof (algo_oid);
  char params_value[2];
  grub_int32_t params_size = sizeof (params_value);
  grub_uint8_t *key_data = NULL;
  grub_int32_t key_size = 0;
  grub_uint32_t key_type;
  grub_size_t i;

  /* Algorithm: see notes for rsaEncryption_oid. */
  rc = asn1_read_value (cert_asn1, algo_name, algo_oid, &algo_size);
  if (rc != ASN1_SUCCESS || algo_size == 0)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading x509 public key algorithm: %s",
                       ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));

  if (x509_is_valid_pkalgo (algo_oid, algo_size - 1) == false)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                       "unsupported x509 public key algorithm: %s", algo_oid);

  for (i = 0; i < sizeof (pk_algos)/sizeof(pk_algos[0]); i++)
    {
      if (pk_algos[i].oid_len == algo_size - 1 &&
          grub_strncmp (algo_oid, pk_algos[i].oid,  pk_algos[i].oid_len) == 0)
        {
          grub_memcpy (&cert->spki.pk_algo, &pk_algos[i], sizeof (pk_algos[i]));
          break;
        }
    }

  if (x509_is_mldsa_algo (algo_oid, algo_size - 1) == false)
    {
      /*
       * RFC 3279 2.3.1 : The rsaEncryption OID is intended to be used in the
       * algorithm field of a value of type AlgorithmIdentifier. The parameters
       * field MUST have ASN.1 type NULL for this algorithm identifier.
       */
      rc = asn1_read_value (cert_asn1, params_name, params_value, &params_size);
      if (rc != ASN1_SUCCESS || params_size == 0)
        return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading x509 public key parameters: %s",
                           ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));

      if (params_value[0] != ASN1_TAG_NULL)
        return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                           "invalid x509 public key parameters: expected NULL");
    }

  /*
   * RFC 3279 2.3.1:  The DER encoded RSAPublicKey is the value of the BIT
   * STRING subjectPublicKey.
   */
  rc = asn1_read_value_type (cert_asn1, pk_name, NULL, &key_size, &key_type);
  if (rc != ASN1_MEM_ERROR || key_size == 0)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of x509 public key: %s",
                       ((rc != ASN1_MEM_ERROR) ? asn1_strerror (rc) : "contains zero bytes"));

  if (key_type != ASN1_ETYPE_BIT_STRING)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "unexpected ASN.1 type when reading x509 public key: %x",
                       key_type);

  /* Length is in bits. */
  key_size = (key_size + 7) / 8;

  key_data = grub_zalloc (key_size + 1);
  if (key_data == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory for x509 public key");

  rc = asn1_read_value (cert_asn1, pk_name, key_data, &key_size);
  if (rc != ASN1_SUCCESS || key_size == 0)
    {
      grub_free (key_data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading public key data: %s",
                         ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
    }

  key_size = (key_size + 7) / 8;
  if (x509_is_mldsa_algo (algo_oid, algo_size - 1) == false)
    {
      ret = x509_get_rsa_pubkey (key_data, key_size, cert);
      grub_free (key_data);
    }
  else
    {
      cert->spki.pk.raw_len = key_size;
      /* Key size byte to bits. */
      key_size = key_size * 8;
      if (x509_is_valid_mldsa_key (key_size) == false)
        {
          grub_free (key_data);
          return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		             "unsupported %s public key: %d",
                             cert->spki.pk_algo.name, key_size);
        }

      cert->spki.pk.raw = key_data;
      cert->spki.pk_len = key_size;
    }

  return ret;
}

/*
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING
 *                  -- contains the DER encoding of an ASN.1 value
 *                  -- corresponding to the extension type identified
 *                  -- by extnID
 * }
 *
 * A certificate must:
 *  - contain the Digital Signature usage
 *  - not be a CA
 *  - contain no extended usages, or contain the Code Signing extended usage
 *  - not contain any other critical extensions (RFC 5280 s 4.2)
 */
static grub_err_t
x509_get_extensions (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  grub_int32_t ext, num_extensions = 0;
  grub_int32_t usage_present = 0, constraints_present = 0, extended_usage_present = 0;
  char *oid_path, *critical_path, *value_path;
  char extnID[GRUB_MAX_OID_LEN];
  grub_int32_t extnID_size;
  grub_err_t ret;
  char critical[6]; /* We get either "TRUE" or "FALSE". */
  grub_int32_t critical_size;
  grub_uint8_t *value;
  grub_int32_t value_size;

  (void) cert;

  rc = asn1_number_of_elements (cert_asn1, "tbsCertificate.extensions", &num_extensions);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting number of extensions: %s",
                       asn1_strerror (rc));

  if (num_extensions < 2)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "insufficient number of extensions for certificate, need at least 2, got %d",
                       num_extensions);

  for (ext = 1; ext <= num_extensions; ext++)
    {
      oid_path = grub_xasprintf ("tbsCertificate.extensions.?%d.extnID", ext);
      if (oid_path == NULL)
        return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error extension OID path is empty");

      extnID_size = sizeof (extnID);
      rc = asn1_read_value (cert_asn1, oid_path, extnID, &extnID_size);
      if (rc != ASN1_SUCCESS || extnID_size == 0)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading extension OID: %s",
                            ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
          goto cleanup_oid_path;
        }

      critical_path = grub_xasprintf ("tbsCertificate.extensions.?%d.critical", ext);
      if (critical_path == NULL)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error critical path is empty");
          goto cleanup_oid_path;
        }

      critical_size = sizeof (critical);
      rc = asn1_read_value (cert_asn1, critical_path, critical, &critical_size);
      if (rc == ASN1_ELEMENT_NOT_FOUND)
        critical[0] = '\0';
      else if (rc != ASN1_SUCCESS || critical_size == 0)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading extension criticality: %s",
                            ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
          goto cleanup_critical_path;
        }

      value_path = grub_xasprintf ("tbsCertificate.extensions.?%d.extnValue", ext);
      if (value_path == NULL)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error extnValue path is empty");
          goto cleanup_critical_path;
        }

      value = grub_asn1_allocate_and_read (cert_asn1, value_path,
                                           "certificate extension value", &value_size);
      if (value == NULL)
        {
          ret = grub_errno;
          goto cleanup_value_path;
        }

      /*
       * Now we must see if we recognise the OID. If we have an unrecognised
       * critical extension we MUST bail.
       */
      if (keyUsage_oid_len == extnID_size - 1 &&
          grub_strncmp (keyUsage_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_key_usage (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          usage_present++;
        }
      else if (basicConstraints_oid_len == extnID_size - 1 &&
               grub_strncmp (basicConstraints_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_basic_constraints (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          constraints_present++;
        }
      else if (extendedKeyUsage_oid_len == extnID_size -1  &&
               grub_strncmp (extendedKeyUsage_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_extended_key_usage (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          extended_usage_present++;
        }
      else if (critical_true_str_len == critical_size - 1 &&
               grub_strncmp (critical_true_str, critical, critical_size) == 0)
        {
          /*
           * Per the RFC, we must not process a certificate with a critical
           * extension we do not understand.
           */
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                            "unhandled critical x509 extension with OID %s", extnID);
          goto cleanup_value;
        }

      grub_free (value);
      grub_free (value_path);
      grub_free (critical_path);
      grub_free (oid_path);
    }

  if (usage_present != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of Key Usage extensions - expected 1, got %d",
                       usage_present);

  if (constraints_present != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of basic constraints extensions - expected 1, got %d",
                       constraints_present);

  if (extended_usage_present > 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of Extended Key Usage extensions - expected 0 or 1, got %d",
                       extended_usage_present);

  return GRUB_ERR_NONE;

 cleanup_value:
  grub_free (value);
 cleanup_value_path:
  grub_free (value_path);
 cleanup_critical_path:
  grub_free (critical_path);
 cleanup_oid_path:
  grub_free (oid_path);

  return ret;
}

static grub_err_t
x509_add_cert_fingerprint (const void *data, const grub_size_t data_size,
                           grub_x509_cert_t *const cert)
{
  cert->fingerprint[GRUB_FINGERPRINT_SHA256] = grub_zalloc (SHA256_HASH_SIZE + 1);
  if (cert->fingerprint[GRUB_FINGERPRINT_SHA256] == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  /* Add SHA256 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha256,
                    cert->fingerprint[GRUB_FINGERPRINT_SHA256], data, data_size);

  cert->fingerprint[GRUB_FINGERPRINT_SHA384] = grub_zalloc (SHA384_HASH_SIZE + 1);
  if (cert->fingerprint[GRUB_FINGERPRINT_SHA384] == NULL)
    {
      grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA256]);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  /* Add SHA384 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha384,
                    cert->fingerprint[GRUB_FINGERPRINT_SHA384], data, data_size);

  cert->fingerprint[GRUB_FINGERPRINT_SHA512] = grub_zalloc (SHA512_HASH_SIZE + 1);
  if (cert->fingerprint[GRUB_FINGERPRINT_SHA512] == NULL)
    {
      grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA256]);
      grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA384]);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  /* Add SHA512 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha512,
                    cert->fingerprint[GRUB_FINGERPRINT_SHA512], data, data_size);

  return GRUB_ERR_NONE;
}

/*
 * Parse a certificate whose DER-encoded form is in @data, of size @data_size.
 * Return the results in @results, which must point to an allocated x509
 * certificate.
 */
static grub_err_t
x509_cert_parse_der (const void *der_data, grub_int32_t der_data_size, grub_x509_cert_t *cert)
{
  grub_int32_t rc = 0;
  grub_err_t ret;
  asn1_node cert_asn1;

  if (cert == NULL || der_data == NULL || der_data_size <= 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  if (der_data_size > (GRUB_INT32_MAX - 1)/2)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "cannot parse a certificate where data size > %d",
                       (GRUB_INT32_MAX - 1)/2);

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.Certificate", &cert_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for certificate: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&cert_asn1, der_data, &der_data_size,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "could not parse DER for certificate: %s", asn1_error);
      goto exit;
    }

  /*
   * TBSCertificate  ::=  SEQUENCE {
   *     version         [0]  EXPLICIT Version DEFAULT v1
   */
  ret = x509_get_version (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * serialNumber         CertificateSerialNumber,
   *
   * CertificateSerialNumber  ::=  INTEGER
   */
  ret = x509_get_serial (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * signature            AlgorithmIdentifier,
   *
   * We don't load the signature or issuer at the moment,
   * as we don't attempt x509 verification.
   */
  /*
   * validity             Validity,
   *
   * Validity ::= SEQUENCE {
   *     notBefore      Time,
   *     notAfter       Time }
   */
  ret = x509_get_validity (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * issuer              Name,
   *
   * This is an X501 name, we parse out just the issuer.
   */
  /*
   * subject              Name,
   *
   * This is an X501 name, we parse out just the CN.
   */
  ret = x509_get_issuer_and_subject (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    subjectPublicKeyInfo SubjectPublicKeyInfo,
   *    ...
   */
  ret = x509_get_subject_public_key (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto cleanup_exit;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    extensions      [3]  EXPLICIT Extensions OPTIONAL
   *                         -- If present, version MUST be v3
   * }
   */
  ret = x509_get_extensions (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto cleanup_pk;

  /* Add the fingerprint of the certificate. */
  ret = x509_add_cert_fingerprint (der_data, der_data_size, cert);
  if (ret != GRUB_ERR_NONE)
    goto cleanup_pk;

  /*
   * We do not read or check the signature on the certificate:
   * as discussed we do not try to validate the certificate but trust
   * it implictly.
   */
  asn1_delete_structure (&cert_asn1);

  return GRUB_ERR_NONE;

 cleanup_pk:
  grub_free (cert->spki.pk.raw);
  _gcry_mpi_release (cert->spki.pk.modulus);
  _gcry_mpi_release (cert->spki.pk.exponent);
 cleanup_exit:
  grub_free (cert->serial);
  grub_free (cert->issuer);
  grub_free (cert->subject);
 exit:
  asn1_delete_structure (&cert_asn1);

  return ret;
}

static bool
x509_fp_cmp (const grub_uint8_t *hash_data, const grub_size_t hash_data_size,
             const grub_x509_cert_t *cert)
{
  grub_int32_t type;

  if (cert == NULL || hash_data == NULL || hash_data_size == 0)
    return false;

  if (hash_data_size == SHA256_HASH_SIZE)
    type = GRUB_FINGERPRINT_SHA256;
  else if (hash_data_size == SHA384_HASH_SIZE)
    type = GRUB_FINGERPRINT_SHA384;
  else if (hash_data_size == SHA512_HASH_SIZE)
    type = GRUB_FINGERPRINT_SHA512;
  else
    {
      grub_dprintf ("appendedsig", "unsupported fingerprint hash type "
                    "(%" PRIuGRUB_SIZE ") \n", hash_data_size);
      return false;
    }

  if (grub_memcmp (cert->fingerprint[type], hash_data, hash_data_size) == 0)
    return true;

  return false;
}

static bool
x509_cert_cmp (const grub_x509_cert_t *cert1, const grub_x509_cert_t *cert2)
{
  if (cert1 == NULL || cert2 == NULL)
    return false;

  if (cert1->subject == NULL || cert2->subject == NULL ||
      cert1->issuer == NULL || cert2->issuer == NULL ||
      cert1->serial == NULL || cert2->serial == NULL)
    return false;

  if (cert1->fingerprint[GRUB_FINGERPRINT_SHA256] == NULL ||
      cert2->fingerprint[GRUB_FINGERPRINT_SHA256] == NULL)
    return false;

  if (cert1->subject_len != cert2->subject_len ||
      cert1->issuer_len != cert2->issuer_len ||
      cert1->serial_len != cert2->serial_len)
    return false;

  if (grub_memcmp (cert1->subject, cert2->subject, cert2->subject_len) != 0 ||
      grub_memcmp (cert1->issuer, cert2->issuer, cert2->issuer_len) != 0 ||
      grub_memcmp (cert1->serial, cert2->serial, cert2->serial_len) != 0)
    return false;

  if ((cert1->spki.pk.modulus != NULL && cert2->spki.pk.modulus  != NULL) &&
      (cert1->spki.pk.exponent != NULL && cert2->spki.pk.exponent != NULL))
    {
      if (_gcry_mpi_cmp (cert1->spki.pk.modulus, cert2->spki.pk.modulus) != 0 ||
          _gcry_mpi_cmp (cert1->spki.pk.exponent, cert2->spki.pk.exponent) != 0)
        return false;
    }
  else if ((cert1->spki.pk.raw_len > 0 &&
            cert1->spki.pk.raw_len == cert2->spki.pk.raw_len) &&
           (cert1->spki.pk.raw != NULL && cert2->spki.pk.raw  != NULL))
    {
      if (grub_memcmp (cert1->spki.pk.raw, cert2->spki.pk.raw,
                       cert2->spki.pk.raw_len) != 0)
        return false;
    }
  else
    return false;

  if (x509_fp_cmp (cert1->fingerprint[GRUB_FINGERPRINT_SHA256],
                   SHA256_HASH_SIZE, cert2) == false)
    return false;

  return true;
}

static void
x509_cert_print (const grub_x509_cert_t *crt)
{
  grub_uint32_t cert_num = 1;
  const grub_x509_cert_t *cert;

  for (cert = crt; cert != NULL; cert = cert->next, cert_num++)
  {
    grub_printf ("\nCertificate: %u\n", cert_num);
    grub_printf ("    Data:\n");
    grub_printf ("        Version: %u (0x%u)\n", cert->version + 1, cert->version);
    grub_printf ("        Serial Number: 0x%s\n", cert->serial);
    grub_printf ("        Issuer: %s\n", cert->issuer);
    grub_printf ("        Subject: %s\n", cert->subject);
    grub_printf ("        Subject Public Key Info:\n");
    grub_printf ("            Public Key Algorithm: %s\n", cert->spki.pk_algo.name);
    grub_printf ("                Public-Key: (%d bit)\n", cert->spki.pk_len);
    grub_printf ("    Fingerprint: sha256\n         ");
    grub_util_hexdump_colon (&cert->fingerprint[GRUB_FINGERPRINT_SHA256][0],
                             SHA256_HASH_SIZE);
  }
}

/*
 * Release all the storage associated with the x509 certificate. If the caller
 * dynamically allocated the certificate, it must free it. The caller is also
 * responsible for maintenance of the linked list.
 */
static void
x509_cert_release (grub_x509_cert_t *cert)
{
  if (cert == NULL)
    return;

  grub_free (cert->issuer);
  grub_free (cert->subject);
  grub_free (cert->serial);
  grub_memset (&cert->validity, 0x00, sizeof (grub_x509_validity_t));
  grub_free (cert->spki.pk.raw);
  _gcry_mpi_release (cert->spki.pk.modulus);
  _gcry_mpi_release (cert->spki.pk.exponent);
  grub_memset (&cert->spki, 0x00, sizeof (grub_x509_spki_t));
  grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA256]);
  grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA384]);
  grub_free (cert->fingerprint[GRUB_FINGERPRINT_SHA512]);
  grub_memset (cert, 0x00, sizeof (grub_x509_cert_t));
}

/* Release the allocated memory. */
static void
x509_cert_free (grub_x509_cert_t *cert)
{
  grub_free (cert);
}

static grub_x509_spec_t _grub_x509_spec =
  {
    "X509",
    x509_fp_cmp,
    x509_cert_cmp,
    x509_cert_print,
    x509_cert_parse_der,
    x509_cert_release,
    x509_cert_free
  };

grub_x509_spec_t *grub_x509_spec = &_grub_x509_spec;
