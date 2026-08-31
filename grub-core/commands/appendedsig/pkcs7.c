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

#include <grub/misc.h>
#include <sys/types.h>
#include <grub/gcrypt/gcrypt.h>

#include "util.h"
#include "asn1_util.h"
#include "pkcs7.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/* RFC 5652 s 5.1. */
static const char *signed_data_oid = "1.2.840.113549.1.7.2";
static const grub_int32_t signed_data_oid_len = 20;
static const char *oid_pkcs7_data = "1.2.840.113549.1.7.1";
static const grub_int32_t oid_pkcs7_data_len = 20;

static const char *common_name_oid = "2.5.4.3";
static const grub_int32_t common_name_oid_len = 7;

/* RFC 4055 s 2.1. */
static const grub_pkcs7_mdalgo_t md_algos[] =
{
  {"sha256", "2.16.840.1.101.3.4.2.1", 22, &_gcry_digest_spec_sha256},
  {"sha512", "2.16.840.1.101.3.4.2.3", 22, &_gcry_digest_spec_sha512}
};

static const grub_pkcs7_sigalgo_t sig_algos[] =
{
  {"rsaEncryption", "rsa", "1.2.840.113549.1.1.1", 20, {256, 384, 512}},
  {"ML-DSA-44", "dilithium2", "2.16.840.1.101.3.4.3.17", 23, {2420, 0, 0}},
  {"ML-DSA-65", "dilithium3", "2.16.840.1.101.3.4.3.18", 23, {3309, 0, 0}},
  {"ML-DSA-87", "dilithium5", "2.16.840.1.101.3.4.3.19", 23, {4627, 0, 0}}
};

static void
pkcs7_free_signers (grub_pkcs7_signer_t *signers);

static void
pkcs7_signed_data_release (grub_pkcs7_signed_data_t *pkcs7_signed_data);

static grub_err_t
pkcs7_get_version (asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  char version;
  grub_int32_t version_size = sizeof (version);

  rc = asn1_read_value (pkcs7_asn1, "version", &version, &version_size);
  if (rc != ASN1_SUCCESS || version_size == 0)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error reading signedData version: %s",
                       ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));

  /* Signature version must be 1 because appended signature only support v1. */
  if (version != 1)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "unexpected signature version v%d, only v1 supported", version);

  pkcs7_signed_data->version = 1;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_md_algo (asn1_node pkcs7_asn1, grub_int32_t algo_index,
                   grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_size_t i;
  char *digest_path;
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_oid_size = sizeof (algo_oid);

  digest_path = grub_xasprintf ("digestAlgorithms.?%d.algorithm", algo_index + 1);
  if (digest_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for digest algorithm parsing path");

  rc = asn1_read_value (pkcs7_asn1, digest_path, algo_oid, &algo_oid_size);
  if (rc != ASN1_SUCCESS || algo_oid_size == 0)
    {
      grub_free (digest_path);
      return grub_error (GRUB_ERR_BAD_SIGNATURE, "error reading digest algorithm: %s",
                         ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
    }

  grub_free (digest_path);

  for (i = 0; i < sizeof (md_algos)/sizeof(md_algos[0]); i++)
    {
      if (md_algos[i].oid_len == algo_oid_size - 1 &&
          grub_strncmp (algo_oid, md_algos[i].oid, md_algos[i].oid_len) == 0)
        {
          grub_memcpy (&pkcs7_signed_data->algo, &md_algos[i], sizeof (md_algos[i]));
          return GRUB_ERR_NONE;
        }
    }

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "only SHA-256 and SHA-512 hashes are supported, found OID %s",
                     algo_oid);
}

static grub_err_t
pkcs7_get_md_algorithms (asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_err_t ret;
  grub_int32_t algo_count;

  rc = asn1_number_of_elements (pkcs7_asn1, "digestAlgorithms", &algo_count);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error counting number of digest algorithms: %s",
                       asn1_strerror (rc));

  if (algo_count <= 0 || algo_count > 1)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "only one digest algorithm is required");

  ret = pkcs7_get_md_algo (pkcs7_asn1, 0, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    return ret;

  return GRUB_ERR_NONE;
}

/*
 * EncapsulatedContentInfo ::= SEQUENCE {
 *   eContentType ContentType,
 *   eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 */
static grub_err_t
pkcs7_get_econtent_info (asn1_node pkcs7_asn1,
                         grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_int32_t len = 0;
  char *econtent_type = NULL;
  const char *name = "encapContentInfo.eContentType";
  const char *name_ec = "encapContentInfo.eContent";

  /* The eContent must be absent for detached signatures. */
  rc = asn1_read_value (pkcs7_asn1, name_ec, NULL, &len);
  if (rc == ASN1_MEM_ERROR || rc == ASN1_VALUE_NOT_FOUND)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                       "embedded content in PKCS#7 message is not supported");

  econtent_type = grub_asn1_allocate_and_read (pkcs7_asn1, name,
                                               "encapContentInfo.eContentType",
                                               &len);
  if (econtent_type == NULL)
    return grub_errno;

  if (oid_pkcs7_data_len != len - 1 ||
      grub_strncmp (oid_pkcs7_data, econtent_type, oid_pkcs7_data_len) != 0)
    {
      grub_free (econtent_type);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                         "eContentType has unsupported type");
    }

  pkcs7_signed_data->eci.type = econtent_type;
  pkcs7_signed_data->eci.type_len = len - 1;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfo_version (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                              grub_pkcs7_signer_t *signer)
{
  grub_int32_t rc;
  char version;
  char *version_path;
  grub_int32_t version_size = sizeof (version);

  version_path = grub_xasprintf ("signerInfos.?%d.version", signer_index + 1);
  if (version_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signer version parsing path",
                       signer_index);

  rc = asn1_read_value (pkcs7_asn1, version_path, &version, &version_size);
  grub_free (version_path);
  if (rc != ASN1_SUCCESS || version_size == 0)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error reading signers version: %s",
                       ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));

  /* Signature version must be 1 because appended signature only support v1. */
  if (version != 1)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "unexpected signature version v%d, only v1 supported", version);

  signer->version = 1;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfo_issuer_and_serial (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                                        grub_pkcs7_signer_t *signer)
{
  grub_err_t ret;
  grub_int32_t signer_id_len = 0;
  grub_int32_t serial_len = 0;
  grub_uint8_t *serial;
  char *sid_path;
  char *serial_path;
  char *issuer_path;
  char *signer_id;

  sid_path = grub_xasprintf ("signerInfos.?%d.sid", signer_index + 1);
  if (sid_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signer identifier parsing path",
                       signer_index);

  signer_id = grub_asn1_allocate_and_read (pkcs7_asn1, sid_path, "signer identifier",
                                           &signer_id_len);
  grub_free (sid_path);
  if (signer_id == NULL)
    return grub_errno;

  if (grub_strncmp (signer_id, "issuerAndSerialNumber", signer_id_len) == 0)
    {
      grub_free (signer_id);
      issuer_path = grub_xasprintf ("signerInfos.?%d.sid.issuerAndSerialNumber.issuer",
                                    signer_index + 1);
      if (issuer_path == NULL)
        return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                           "could not allocate path for signer %d's issuer parsing path",
                           signer_index);

      ret = grub_asn1_read_rnd_sequence (pkcs7_asn1, issuer_path, common_name_oid,
                                         common_name_oid_len, &signer->issuer,
                                         &signer->issuer_len);
      grub_free (issuer_path);
      if (ret != GRUB_ERR_NONE)
        return ret;

      serial_path = grub_xasprintf ("signerInfos.?%d.sid.issuerAndSerialNumber.serialNumber",
                                    signer_index + 1);
      if (serial_path == NULL)
        {
          grub_free (signer->issuer);
          return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                             "could not allocate path for signer %d's serialNumber parsing path",
                             signer_index);
	}

      serial = grub_asn1_allocate_and_read (pkcs7_asn1, serial_path, "serial number",
                                            &serial_len);
      grub_free (serial_path);
      if (serial == NULL)
        {
          grub_free (signer->issuer);
          return grub_errno;
	}

      ret = grub_util_buffer2hex (serial, serial_len, &signer->serial,
                                  &signer->serial_len);
      grub_free (serial);
      if (ret != GRUB_ERR_NONE)
        {
          grub_free (signer->issuer);
          return ret;
	}
    }
  else
      grub_free (signer_id);

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfo_md_algo (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                              grub_pkcs7_signer_t *signer)
{
  grub_int32_t rc;
  grub_size_t i;
  char *digest_algo_path;
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_oid_size = sizeof (algo_oid);

  digest_algo_path = grub_xasprintf ("signerInfos.?%d.digestAlgorithm.algorithm",
                                     signer_index + 1);
  if (digest_algo_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's digest algorithm parsing path",
                       signer_index);

  rc = asn1_read_value (pkcs7_asn1, digest_algo_path, algo_oid, &algo_oid_size);
  if (rc != ASN1_SUCCESS || algo_oid_size == 0)
    {
      grub_free (digest_algo_path);
      return grub_error (GRUB_ERR_BAD_SIGNATURE,
                         "error reading signer %d's digest algorithm: %s", signer_index,
                         ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
    }

  grub_free (digest_algo_path);

  for (i = 0; i < sizeof (md_algos)/sizeof(md_algos[0]); i++)
    {
      if (md_algos[i].oid_len == algo_oid_size - 1 &&
          grub_strncmp (algo_oid, md_algos[i].oid, md_algos[i].oid_len) == 0)
        {
          grub_memcpy (&signer->md_algo, &md_algos[i], sizeof (md_algos[i]));
          return GRUB_ERR_NONE;
        }
    }

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "only SHA-256 and SHA-512 hashes are supported, found OID %s",
                     algo_oid);
}

static grub_err_t
pkcs7_get_signerinfo_signed_attrs (const grub_uint8_t *raw_data,
                                   const grub_int32_t raw_data_len,
                                   const asn1_node pkcs7_asn1,
                                   const grub_int32_t signer_index,
                                   grub_pkcs7_signer_t *signer)
{
  grub_int32_t rc;
  grub_int32_t start_off = 0;
  grub_int32_t end_off = 0;
  grub_int32_t attr_raw_len;
  grub_uint8_t *attr_raw;
  char *signed_attr_path;

  signed_attr_path = grub_xasprintf ("signerInfos.?%d.signedAttrs", signer_index + 1);
  if (signed_attr_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signedattr parsing path",
                       signer_index);

  rc = asn1_der_decoding_startEnd (pkcs7_asn1, raw_data, raw_data_len,
                                   signed_attr_path, &start_off, &end_off);
  grub_free (signed_attr_path);
  if (rc == ASN1_SUCCESS)
    {
      attr_raw_len = end_off - start_off + 1;
      if (start_off < 0 || end_off >= raw_data_len || attr_raw_len <= 0)
        return grub_error (GRUB_ERR_BAD_FILE_TYPE, "Malformed ASN1 memory window bounds");

      attr_raw = grub_malloc (attr_raw_len);
      if (attr_raw == NULL)
        return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                           "could not allocate memory for signer %d's signedattrs",
                           signer_index);

      /* Copy the raw signedAttrs. */
      grub_memcpy (attr_raw, &raw_data[start_off], attr_raw_len);

      /*
       * Perform PKCS#7 Implicit Tag Correction. The signedAttrs uses an ASN.1
       * Implicit tag context mapping ([0] IMPLICIT SET OF Attribute).
       * For crypto-validation matching, the signature expects a basic SET tag (0x31).
       */
      if (attr_raw[0] == 0xA0)
        attr_raw[0] = 0x31;
      else
        {
          grub_free (attr_raw);
          return grub_error (GRUB_ERR_BAD_SIGNATURE,
                             "Unexpected outer implicit tag (Expected 0xA0)");
        }

      signer->signed_attrs.raw = attr_raw;
      signer->signed_attrs.raw_len = attr_raw_len;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfo_sig_algo (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                               grub_pkcs7_signer_t *signer)
{
  grub_int32_t rc;
  grub_size_t i;
  char *sig_algo_path;
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_oid_size = sizeof (algo_oid);

  sig_algo_path = grub_xasprintf ("signerInfos.?%d.signatureAlgorithm.algorithm",
                                  signer_index + 1);
  if (sig_algo_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signature algorithm parsing path",
                       signer_index);

  rc = asn1_read_value (pkcs7_asn1, sig_algo_path, algo_oid, &algo_oid_size);
  if (rc != ASN1_SUCCESS || algo_oid_size == 0)
    {
      grub_free (sig_algo_path);
      return grub_error (GRUB_ERR_BAD_SIGNATURE,
                         "error reading signer %d's signature algorithm: %s", signer_index,
                         ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
    }

  grub_free (sig_algo_path);

  for (i = 0; i < sizeof (sig_algos)/sizeof(sig_algos[0]); i++)
    {
      if (sig_algos[i].oid_len == algo_oid_size - 1 &&
          grub_strncmp (algo_oid, sig_algos[i].oid, sig_algos[i].oid_len) == 0)
        {
          grub_memcpy (&signer->sig_algo, &sig_algos[i], sizeof (sig_algos[i]));
          return GRUB_ERR_NONE;
        }
    }

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "only rsaEncryption and ML-DSA are supported, found OID %s", algo_oid);
}

static bool
pkcs7_is_valid_sig (const grub_pkcs7_signer_t *signer, const grub_int32_t sig_len)
{
  grub_size_t i = 0;

  if (sig_algos[0].oid_len == signer->sig_algo.oid_len &&
      grub_strncmp (signer->sig_algo.oid, sig_algos[0].oid,
                    sig_algos[0].oid_len) == 0)
    {
      if (signer->sig_algo.sig_len[0] == sig_len ||
          signer->sig_algo.sig_len[1] == sig_len ||
          signer->sig_algo.sig_len[2] == sig_len)
        return true;
    }
  else
    {
      for (i = 1; i < sizeof (sig_algos)/sizeof(sig_algos[0]); i++)
        {
          if (sig_algos[i].oid_len == signer->sig_algo.oid_len &&
              grub_strncmp (signer->sig_algo.oid, sig_algos[i].oid,
                            sig_algos[i].oid_len) == 0)
            return (signer->sig_algo.sig_len[0] == sig_len);
        }
    }

  return false;
}

static grub_err_t
pkcs7_get_signerinfo_signature (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                                grub_pkcs7_signer_t *signer)
{
  grub_uint8_t *signature;
  grub_int32_t signature_len = 0;
  char *sig_path;

  sig_path = grub_xasprintf ("signerInfos.?%d.signature", signer_index + 1);
  if (sig_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signature parsing path",
                       signer_index);

  signature = grub_asn1_allocate_and_read (pkcs7_asn1, sig_path, "signature data",
                                           &signature_len);
  grub_free (sig_path);
  if (signature == NULL)
    return grub_errno;

  if (pkcs7_is_valid_sig (signer, signature_len) == true)
    {
      signer->sig = signature;
      signer->sig_len = signature_len;
      return GRUB_ERR_NONE;
    }

  grub_free (signature);

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "unsupported signature: %d", signature_len);
}

static grub_err_t
pkcs7_get_signerinfos (const grub_uint8_t *raw_data, const grub_int32_t raw_data_len,
                       const asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_err_t ret = GRUB_ERR_NONE;
  grub_int32_t rc, i;
  grub_int32_t signer_count;
  grub_pkcs7_signer_t *signer, *signers = pkcs7_signed_data->signers;

  rc = asn1_number_of_elements (pkcs7_asn1, "signerInfos", &signer_count);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error counting number of signers: %s",
                       asn1_strerror (rc));

  if (signer_count <= 0)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "a minimum of 1 signer is required");

  pkcs7_signed_data->no_of_signers = 0;

  for (i = 0; i < signer_count; i++)
    {
      signer = grub_zalloc (sizeof (grub_pkcs7_signer_t));
      if (signer == NULL)
        {
          ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                            "could not allocate space for signers");
          break;
        }

      ret = pkcs7_get_signerinfo_version (pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      ret = pkcs7_get_signerinfo_issuer_and_serial (pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      ret = pkcs7_get_signerinfo_md_algo (pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      ret = pkcs7_get_signerinfo_signed_attrs (raw_data, raw_data_len,
                                               pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      ret = pkcs7_get_signerinfo_sig_algo (pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      ret = pkcs7_get_signerinfo_signature (pkcs7_asn1, i, signer);
      if (ret != GRUB_ERR_NONE)
        break;

      signer->next = (signers != NULL ? signers : NULL);
      signers = signer;
      pkcs7_signed_data->no_of_signers++;
    }

  if (ret != GRUB_ERR_NONE)
    pkcs7_free_signers (signer);

  pkcs7_signed_data->signers = signers;

  return ret;
}

static grub_err_t
pkcs7_parse_signed_data (grub_uint8_t *signed_data, grub_int32_t signed_data_len,
                         grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_err_t ret;
  grub_int32_t rc;
  asn1_node pkcs7_asn1;

  /*
   * SignedData ::= SEQUENCE {
   *     version CMSVersion,
   *     digestAlgorithms DigestAlgorithmIdentifiers,
   *     encapContentInfo EncapsulatedContentInfo,
   *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
   *     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
   *     signerInfos SignerInfos }
   */
  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.pkcs-7-SignedData", &pkcs7_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for PKCS#7 signed part");

  rc = asn1_der_decoding2 (&pkcs7_asn1, signed_data, &signed_data_len,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "error reading PKCS#7 signed data: %s", asn1_error);
      goto exit;
    }

  /* version CMSVersion */
  ret = pkcs7_get_version (pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * digestAlgorithms DigestAlgorithmIdentifiers
   *
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * DigestAlgorithmIdentifer is an X.509 AlgorithmIdentifier (10.1.1)
   *
   * RFC 4055 s 2.1:
   * sha256Identifier  AlgorithmIdentifier  ::=  { id-sha256, NULL }
   * sha512Identifier  AlgorithmIdentifier  ::=  { id-sha512, NULL }
   *
   * We only support 1 element in the set, and we do not check parameters atm.
   */
  ret = pkcs7_get_md_algorithms (pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * EncapsulatedContentInfo ::= SEQUENCE {
   *   eContentType ContentType,
   *   eContent [0] EXPLICIT OCTET STRING OPTIONAL
   * }
   */
  ret = pkcs7_get_econtent_info (pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /* Read the signerInfos */
  ret = pkcs7_get_signerinfos (signed_data, signed_data_len, pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    pkcs7_signed_data_release (pkcs7_signed_data);

 exit:
  asn1_delete_structure (&pkcs7_asn1);

  return ret;
}

/* Parse a single DER formatted PKCS#7 detached signature. */
static grub_err_t
pkcs7_signed_data_parse_der (const void *der_data, grub_int32_t der_data_len,
                             grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_err_t ret = GRUB_ERR_NONE;
  asn1_node cms_content_asn1;
  char content_type_oid[GRUB_MAX_OID_LEN];
  grub_uint8_t *cms_content;
  grub_int32_t cms_content_len;
  grub_int32_t content_type_oid_size = sizeof (content_type_oid);

  if (der_data == NULL || der_data_len <= 0 || pkcs7_signed_data == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  if (der_data_len > (GRUB_INT32_MAX - 1)/2)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "cannot parse a PKCS#7 message where data size > GRUB_UINT_MAX");

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.pkcs-7-ContentInfo",
                            &cms_content_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for PKCS#7 data: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&cms_content_asn1, der_data, &der_data_len,
                           ASN1_DECODE_FLAG_STRICT_DER | ASN1_DECODE_FLAG_ALLOW_PADDING,
                           asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error decoding PKCS#7 message DER: %s", asn1_error);
      goto exit;
    }

  /*
   * ContentInfo ::= SEQUENCE {
   *     contentType ContentType,
   *     content [0] EXPLICIT ANY DEFINED BY contentType }
   *
   * ContentType ::= OBJECT IDENTIFIER
   */
  rc = asn1_read_value (cms_content_asn1, "contentType", content_type_oid,
                        &content_type_oid_size);
  if (rc != ASN1_SUCCESS || content_type_oid_size == 0)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading PKCS#7 content type: %s",
                        ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
      goto exit;
    }

  /* OID for SignedData defined in 5.1. */
  if (signed_data_oid_len != content_type_oid_size - 1 ||
      grub_strncmp (signed_data_oid, content_type_oid, content_type_oid_size) != 0)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "unexpected content type in PKCS#7 message: OID %s",
                        content_type_oid);
      goto exit;
    }

  cms_content = grub_asn1_allocate_and_read (cms_content_asn1, "content",
                                             "PKCS#7 message content", &cms_content_len);
  if (cms_content == NULL)
    {
      ret = grub_errno;
      goto exit;
    }

  grub_memset (pkcs7_signed_data, 0x00, sizeof (grub_pkcs7_signed_data_t));
  ret = pkcs7_parse_signed_data (cms_content, cms_content_len, pkcs7_signed_data);
  grub_free (cms_content);

 exit:
  asn1_delete_structure (&cms_content_asn1);

  return ret;
}

static grub_err_t
pkcs7_check_cert_aginst_rcl (const grub_pkcs7_rcl_t *rcl, const grub_x509_cert_t *pk)
{
  grub_x509_cert_t *cert;

  for (cert = rcl->certs; cert != NULL; cert = cert->next)
    {
      if (grub_x509_spec->cert_cmp (cert, pk) == true)
        {
          grub_dprintf ("appendedsig",
                        "key with PK-Algorithm (%s), issuer ('%s'), and serialNumber (%s)"
                        " is present in the revoked list\n",
                        pk->spki.pk_algo.name, pk->issuer, pk->serial);
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  return GRUB_ERR_NONE;
}

/* Check the certificate presence in the revoked certificate list (rcl). */
static grub_err_t
pkcs7_check_aginst_rcl (const grub_pkcs7_rcl_t *rcl, const grub_x509_cert_t *pk)
{
  grub_pkcs7_hash_t *curr_hash;
  grub_err_t ret;

  ret = pkcs7_check_cert_aginst_rcl (rcl, pk);
  if (ret != GRUB_ERR_NONE)
    return ret;

  for (curr_hash = rcl->hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    {
      if (grub_x509_spec->fp_cmp (curr_hash->hash, curr_hash->hash_size, pk) == true)
        {
          grub_dprintf ("appendedsig",
                        "key with PK-Algorithm (%s), issuer ('%s'), and serialNumber (%s)"
                        " is present in the revoked list\n",
                        pk->spki.pk_algo.name, pk->issuer, pk->serial);
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  return ret;
}

static grub_err_t
pkcs7_get_signer_cert (const grub_pkcs7_signer_t *signer,
                       const grub_x509_cert_t *trust_certs,
                       const grub_pkcs7_rcl_t *rcl,
                       const grub_x509_cert_t **signer_cert,
                       bool *cert_revoked)
{
  grub_err_t ret = GRUB_ERR_BAD_SIGNATURE;
  const grub_x509_cert_t *pk;

  for (pk = trust_certs; pk != NULL; pk = pk->next)
    {
      if ((signer->serial_len == pk->serial_len &&
           grub_memcmp (pk->serial, signer->serial, signer->serial_len) == 0) &&
          (signer->issuer_len == pk->issuer_len &&
           grub_memcmp (pk->issuer, signer->issuer, signer->issuer_len) == 0))
        {
          ret = pkcs7_check_aginst_rcl (rcl, pk);
          if (ret == GRUB_ERR_NONE)
            *signer_cert = pk;
          else
            *cert_revoked = true;

          return ret;
        }
    }

  grub_dprintf ("appendedsig", "expecting key with PK-Algorithm (%s), issuer ('%s'),"
                               " and serialNumber (%s) but not found\n",
                signer->sig_algo.name, signer->issuer, signer->serial);

  return ret;
}

static grub_err_t
pkcs7_signed_data_verify (const grub_pkcs7_signed_data_t *pkcs7,
                          const grub_x509_cert_t *trust_certs,
                          const grub_pkcs7_rcl_t *rcl,
                          const grub_uint8_t *data,
                          const grub_size_t data_len,
                          bool *cert_revoked)
{
  grub_int32_t i = 0;
  grub_err_t ret = GRUB_ERR_BAD_SIGNATURE;
  grub_pkcs7_signer_t *signer;
  const grub_x509_cert_t *pk;

  if (pkcs7 == NULL || trust_certs == NULL || data == NULL ||
      data_len == 0 || cert_revoked == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  if (pkcs7->no_of_signers == 0 || pkcs7->signers == NULL)
    return grub_error (GRUB_ERR_BAD_NUMBER, "no PKCS7 signatures to verify");

  for (signer = pkcs7->signers; signer != NULL; signer = signer->next, i++)
    {
      ret = pkcs7_get_signer_cert (signer, trust_certs, rcl, &pk, cert_revoked);
      if (ret != GRUB_ERR_NONE)
        continue;

      if (signer->signed_attrs.raw != NULL)
        ret = pk->spki.pk_algo.verify (signer->signed_attrs.raw,
                                       signer->signed_attrs.raw_len,
                                       signer->md_algo.hash,
                                       signer->sig, signer->sig_len,
                                       &pk->spki.pk, pk->spki.pk_algo.aliases);
      else
        ret = pk->spki.pk_algo.verify (data, data_len, signer->md_algo.hash,
                                       signer->sig, signer->sig_len,
                                       &pk->spki.pk, pk->spki.pk_algo.aliases);
      if (ret == GRUB_ERR_NONE)
        {
          grub_dprintf ("appendedsig",
                        "verify signer %d signatureAlgorithm (%s), issuer ('%s'), and "
                        "serialNumber (%s) with key PK-Algorithm (%s), issuer ('%s'), "
                        "and serialNumber (%s) succeeded\n",
                        i, signer->sig_algo.name, signer->issuer, signer->serial,
                        pk->spki.pk_algo.name, pk->issuer, pk->serial);
          return ret;
        }

      grub_dprintf ("appendedsig",
                    "verify signer %d signatureAlgorithm (%s), issuer ('%s'), and "
                    "serialNumber (%s) with key PK-Algorithm (%s), issuer ('%s'), "
                    "and serialNumber (%s) failed\n",
                    i, signer->sig_algo.name, signer->issuer, signer->serial,
                    pk->spki.pk_algo.name, pk->issuer, pk->serial);
    }

  return ret;
}

static void
pkcs7_free_signers (grub_pkcs7_signer_t *signers)
{
  grub_pkcs7_signer_t *prev_signer;

  while (signers != NULL)
    {
      grub_free (signers->serial);
      grub_free (signers->issuer);
      grub_memset (&signers->md_algo, 0x00, sizeof (grub_pkcs7_mdalgo_t));
      grub_free (signers->signed_attrs.raw);
      grub_memset (&signers->signed_attrs, 0x00, sizeof (grub_pkcs7_signedattr_t));
      grub_memset (&signers->sig_algo, 0x00, sizeof (grub_pkcs7_sigalgo_t));
      grub_free (signers->sig);
      prev_signer = signers;
      signers = signers->next;
      grub_free (prev_signer);
    }
}

/*
 * Release all the storage associated with the PKCS#7 message. If the caller
 * dynamically allocated the message, it must free it.
 */
static void
pkcs7_signed_data_release (grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  if (pkcs7_signed_data == NULL)
    return;

  pkcs7_signed_data->version = 0;
  grub_memset (&pkcs7_signed_data->algo, 0x00, sizeof (grub_pkcs7_mdalgo_t));
  grub_free (pkcs7_signed_data->eci.type);
  grub_memset (&pkcs7_signed_data->eci, 0x00, sizeof (grub_pkcs7_eci_t));
  pkcs7_free_signers (pkcs7_signed_data->signers);
  grub_memset (pkcs7_signed_data, 0x00, sizeof (grub_pkcs7_signed_data_t));
}

/* Release the alloacted memory. */
static void
pkcs7_signed_data_free (grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_free (pkcs7_signed_data);
}

static grub_pkcs7_spec_t _grub_pkcs7_spec =
  {
    "PKCS7",
    pkcs7_signed_data_parse_der,
    pkcs7_signed_data_verify,
    pkcs7_signed_data_release,
    pkcs7_signed_data_free
  };

grub_pkcs7_spec_t *grub_pkcs7_spec = &_grub_pkcs7_spec;
