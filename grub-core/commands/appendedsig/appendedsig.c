/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2021, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022, 2025 IBM Corporation
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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/command.h>
#include <grub/crypto.h>
#include <grub/i18n.h>
#include <grub/gcrypt/gcrypt.h>
#include <grub/kernel.h>
#include <grub/extcmd.h>
#include <grub/verify.h>
#include <libtasn1.h>
#include <grub/env.h>
#include <grub/lockdown.h>
#if !defined(GRUB_MACHINE_EMU)
#include <grub/powerpc/ieee1275/platform_keystore.h>
#endif
#include <grub/efi/pks.h>

#include "util.h"
#include "asn1_util.h"
#include "x509.h"
#include "pkcs7.h"
#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* The db list is used to validate appended signatures. */
static grub_append_sd_t db = {.certs = NULL, .no_of_certs = 0, .hashes = NULL,
                              .no_of_hashes = 0, .is_db = true};
/*
 * The dbx list is used to ensure that the distrusted certificates or GRUB
 * modules/kernel binaries are rejected during appended signatures/hashes
 * validation.
 */
static grub_append_sd_t dbx = {.certs = NULL, .no_of_certs = 0, .hashes = NULL,
                               .no_of_hashes = 0, .is_db = false};

/*
 * Signature verification flag (check_sigs).
 * check_sigs: false
 *  - No signature verification. This is the default.
 * check_sigs: true
 *  - Enforce signature verification, and if signature verification fails, post
 *    the errors and stop the boot.
 */
static bool check_sigs = false;

/*
 * append_key_mgmt: Key Management Modes
 * False: Static key management (use built-in Keys). This is default.
 * True: Dynamic key management (use Platform KeySotre).
 */
static bool append_key_mgmt = false;

#if !defined(GRUB_MACHINE_EMU)
/* Platform KeyStore db and dbx. */
static grub_pks_t *pks_keystore;
#endif

/* Appended signature size. */
static grub_size_t append_sig_len = 0;

static const struct grub_arg_option options[] =
{
  {"binary-hash", 'b', 0, N_("hash file of the binary."), 0, ARG_TYPE_PATHNAME},
  {"cert-hash", 'c', 1, N_("hash file of the certificate."), 0, ARG_TYPE_PATHNAME},
  {0, 0, 0, 0, 0, 0}
};

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
  return len;
}

/* Filesystem descriptor. */
static struct grub_fs pseudo_fs = {
  .name = "pseudo",
  .fs_read = pseudo_read
};

/*
 * GUID can be used to determine the hashing function and generate the hash using
 * determined hashing function.
 */
static grub_err_t
get_hash (const grub_packed_guid_t *guid, const grub_uint8_t *data, const grub_size_t data_size,
          grub_uint8_t *hash, grub_size_t *hash_size)
{
  gcry_md_spec_t *hash_func = NULL;

  if (guid == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "GUID is not available");

  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha256;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha384;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "unsupported GUID hash");

  grub_crypto_hash (hash_func, hash, data, data_size);
  *hash_size = hash_func->mdlen;

  return GRUB_ERR_NONE;
}

/* Check the hash presence in the db/dbx list. */
static bool
check_hash_presence (const grub_uint8_t *const hash, const grub_size_t hash_size,
                     const grub_append_sd_t *sd)
{
  grub_hash_t *curr_hash;

  for (curr_hash = sd->hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    if (hash_size == curr_hash->hash_size &&
        grub_memcmp (curr_hash->hash, hash, hash_size) == 0)
      return true;

  return false;
}

/* Check the certificate presence in the db/dbx list. */
static bool
check_cert_presence (const grub_x509_cert_t *cert_in, const grub_append_sd_t *sd)
{
  grub_x509_cert_t *cert;

  for (cert = sd->certs; cert != NULL; cert = cert->next)
    if (grub_x509_spec->cert_cmp (cert, cert_in) == true)
      return true;

  return false;
}

/* Check the certificate/ certificate hash presence in the dbx list. */
static bool
check_aginst_dbx (const grub_x509_cert_t *key, grub_uint8_t const *hash,
                  const grub_size_t hash_size, const bool is_hash)
{
  const grub_x509_cert_t *cert;

  if (is_hash == true && hash != NULL && hash_size > 0)
    {
      if (check_hash_presence (hash, hash_size, &dbx) == true)
        return true;

      for (cert = dbx.certs; cert != NULL; cert = cert->next)
        if (grub_x509_spec->fp_cmp (hash, hash_size, cert) == true)
          return true;
    }

  if (is_hash == false && key != NULL)
    {
      if (check_cert_presence (key, &dbx) == true)
        return true;

      if (check_hash_presence (key->fingerprint[GRUB_FINGERPRINT_SHA256],
                               SHA256_HASH_SIZE, &dbx) == true ||
          check_hash_presence (key->fingerprint[GRUB_FINGERPRINT_SHA384],
                               SHA384_HASH_SIZE, &dbx) == true ||
          check_hash_presence (key->fingerprint[GRUB_FINGERPRINT_SHA512],
                               SHA512_HASH_SIZE, &dbx) == true)
        return true;
    }

  return false;
}

/* Add the certificate/binary hash into the db/dbx list. */
static grub_err_t
add_hash (grub_uint8_t *const data, const grub_size_t data_size, const bool is_pks,
          grub_append_sd_t *sd)
{
  grub_hash_t *new_hash;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "certificate/binary-hash data or size is not available");

  if (data_size != SHA256_HASH_SIZE && data_size != SHA384_HASH_SIZE &&
      data_size != SHA512_HASH_SIZE)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "unsupported hash size: %zu", data_size);

  if (sd->is_db == true && is_pks == false)
    {
      if (check_aginst_dbx (NULL, data, data_size, true) == true)
        {
          grub_dprintf ("appendedsig",
                        "cannot add a hash (%02x%02x%02x%02x), as it is present in the dbx list\n",
                        data[0], data[1], data[2], data[3]);
          return GRUB_ERR_ACCESS_DENIED;
        }
    }

  if (check_hash_presence (data, data_size, sd) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a hash (%02x%02x%02x%02x), as it is present in the %s list\n",
                    data[0], data[1], data[2], data[3], ((sd->is_db == true) ? "db" : "dbx"));
      return GRUB_ERR_EXISTS;
    }

  new_hash = grub_zalloc (sizeof (grub_hash_t));
  if (new_hash == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  grub_dprintf ("appendedsig",
                "added the hash %02x%02x%02x%02x... with size of %" PRIuGRUB_SIZE " to the %s list\n",
                data[0], data[1], data[2], data[3], data_size,
                ((sd->is_db == true) ? "db" : "dbx"));

  new_hash->hash = grub_zalloc (data_size + 1);
  if (new_hash->hash == NULL)
    {
      grub_free (new_hash);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  grub_memcpy (new_hash->hash, data, data_size);
  new_hash->hash_size = data_size;
  new_hash->next = (sd->hashes != NULL ? sd->hashes : NULL);
  sd->hashes = new_hash;
  sd->no_of_hashes++;

  return GRUB_ERR_NONE;
}

#if !defined(GRUB_MACHINE_EMU)
static bool
is_hash (const grub_packed_guid_t *guid)
{
  /* GUID type of the binary hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  /* GUID type of the certificate hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}

static bool
is_x509 (const grub_packed_guid_t *guid)
{
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}
#endif

/*
 * Add the certificate into the db list if it is not present in the dbx and db
 * list when is_db is true. Add the certificate into the dbx list when is_db is
 * false.
 */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 const bool is_pks, grub_append_sd_t *sd)
{
  grub_err_t rc;
  grub_x509_cert_t *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (grub_x509_cert_t));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_x509_spec->parse_der (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot add a certificate CN='%s' to the %s list\n",
                    cert->subject, (sd->is_db == true) ? "db" : "dbx");
      grub_x509_spec->free (cert);
      return rc;
    }

  /*
   * Only checks the certificate against dbx if is_db is true when dynamic key
   * management is enabled.
   */
  if (append_key_mgmt == true)
    {
      if (sd->is_db == true && is_pks == false)
        {
          if (check_aginst_dbx (cert, NULL, 0, false) == true)
            {
              grub_dprintf ("appendedsig",
                            "cannot add a certificate CN='%s', as it is present in the dbx list",
                            cert->subject);
              rc = GRUB_ERR_ACCESS_DENIED;
              goto fail;
            }
        }
    }

  if (check_cert_presence (cert, sd) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a certificate CN='%s', as it is present in the %s list",
                    cert->subject, ((sd->is_db == true) ? "db" : "dbx"));
      rc = GRUB_ERR_EXISTS;
      goto fail;
    }

  grub_dprintf ("appendedsig", "added a certificate CN='%s' to the %s list\n",
                cert->subject, ((sd->is_db == true) ? "db" : "dbx"));

  cert->next = sd->certs;
  sd->certs = cert;
  sd->no_of_certs++;

  return rc;

 fail:
  grub_x509_spec->release (cert);
  grub_x509_spec->free (cert);

  return rc;
}

static void
_remove_cert_from_db (const grub_x509_cert_t *cert)
{
  grub_uint32_t i = 1;
  grub_x509_cert_t *curr_cert, *prev_cert;

  for (curr_cert = prev_cert = db.certs; curr_cert != NULL; curr_cert = curr_cert->next, i++)
    {
      if (grub_x509_spec->cert_cmp (curr_cert, cert) == true)
        {
          if (i == 1) /* Match with first certificate in the db list. */
            db.certs = curr_cert->next;
          else
            prev_cert->next = curr_cert->next;

          grub_dprintf ("appendedsig",
                        "removed distrusted certificate with CN: %s from the db list\n",
                        curr_cert->subject);
          curr_cert->next = NULL;
          grub_x509_spec->release (curr_cert);
          grub_x509_spec->free (curr_cert);
          db.no_of_certs--;
          break;
        }
      else
        prev_cert = curr_cert;
    }
}

static grub_err_t
remove_cert_from_db (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc;
  grub_x509_cert_t *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (grub_x509_cert_t));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_x509_spec->parse_der (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot remove an invalid certificate from the db list\n");
      grub_free (cert);
      return rc;
    }

  /* Remove certificate from the db list. */
  _remove_cert_from_db (cert);

  return rc;
}

static grub_err_t
file_read_whole (grub_file_t file, grub_uint8_t **buf, grub_size_t *len)
{
  grub_off_t full_file_size;
  grub_size_t file_size, total_read_size = 0;
  grub_ssize_t read_size;

  full_file_size = grub_file_size (file);
  if (full_file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "cannot read a file of unknown size into a buffer");

  if (full_file_size > GRUB_SIZE_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "file is too large to read: %" PRIuGRUB_OFFSET " bytes",
                       full_file_size);

  file_size = (grub_size_t) full_file_size;
  *buf = grub_zalloc (file_size + 1);
  if (*buf == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate file data buffer size %" PRIuGRUB_SIZE,
                       file_size);

  while (total_read_size < file_size)
    {
      read_size = grub_file_read (file, *buf + total_read_size, file_size - total_read_size);
      if (read_size < 0)
        {
          grub_free (*buf);
          return grub_errno;
        }
      else if (read_size == 0)
        {
          grub_free (*buf);
          return grub_error (GRUB_ERR_IO,
                             "could not read full file size "
                             "(%" PRIuGRUB_SIZE "), only %" PRIuGRUB_SIZE " bytes read",
                             file_size, total_read_size);
        }

      total_read_size += read_size;
    }

  *len = file_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
extract_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize,
                            grub_append_sig_t *sig)
{
  grub_size_t appendedsig_pkcs7_size;
  grub_size_t signed_data_size = bufsize;
  const grub_uint8_t *signed_data = buf;

  if (signed_data_size < SIG_MAGIC_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature magic");

  /* Fast-forwarding pointer and get signature magic string. */
  signed_data += signed_data_size - SIG_MAGIC_SIZE;
  if (grub_strncmp ((const char *) signed_data, SIG_MAGIC, SIG_MAGIC_SIZE))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "missing or invalid signature magic");

  signed_data_size -= SIG_MAGIC_SIZE;
  if (signed_data_size < SIG_METADATA_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature metadata");

  /* Rewind pointer and extract signature metadata. */
  signed_data -= SIG_METADATA_SIZE;
  grub_memcpy (&(sig->sig_metadata), signed_data, SIG_METADATA_SIZE);

  if (sig->sig_metadata.id_type != PKEY_ID_PKCS7)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "wrong signature type");

  appendedsig_pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  signed_data_size -= SIG_METADATA_SIZE;
  if (appendedsig_pkcs7_size > signed_data_size)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for PKCS#7 message");

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", appendedsig_pkcs7_size);

  /* Appended signature size. */
  sig->signature_len = APPENDED_SIG_SIZE (appendedsig_pkcs7_size);
  /* Rewind pointer and parse appended pkcs7 data. */
  signed_data -= appendedsig_pkcs7_size;

  return grub_pkcs7_spec->parse_der (signed_data, appendedsig_pkcs7_size, &sig->pkcs7);
}

static grub_err_t
get_binary_hash (const grub_size_t binary_hash_size, const grub_uint8_t *data,
                 const grub_size_t data_size, grub_uint8_t *hash, grub_size_t *hash_size)
{
  grub_packed_guid_t guid = { 0 };

  /* support SHA256, SHA384 and SHA512 for binary hash */
  if (binary_hash_size == SHA256_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE);
  else if (binary_hash_size == SHA384_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE);
  else if (binary_hash_size == SHA512_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE);
  else
    {
      grub_dprintf ("appendedsig", "unsupported hash type (%" PRIuGRUB_SIZE ") and "
                    "skipped\n", binary_hash_size);
      return GRUB_ERR_UNKNOWN_COMMAND;
    }

  return get_hash (&guid, data, data_size, hash, hash_size);
}

/*
 * Verify binary hash against the db and dbx list.
 * The following errors can occur:
 *  - GRUB_ERR_BAD_SIGNATURE: indicates that the hash is in dbx list.
 *  - GRUB_ERR_EOF: the hash could not be found in the db and dbx list.
 *  - GRUB_ERR_NONE: the hash is found in db list.
 */
static grub_err_t
verify_binary_hash (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t hash_size = 0;
  grub_uint8_t hash[GRUB_MAX_HASH_LEN] = { 0 };
  grub_hash_t *curr_hash;

  for (curr_hash = dbx.hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    {
      rc = get_binary_hash (curr_hash->hash_size, data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == curr_hash->hash_size &&
          grub_memcmp (curr_hash->hash, hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "the hash (%02x%02x%02x%02x) is present in the dbx list\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  for (curr_hash = db.hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    {
      rc = get_binary_hash (curr_hash->hash_size, data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == curr_hash->hash_size &&
          grub_memcmp (curr_hash->hash, hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "verified with a trusted hash (%02x%02x%02x%02x)\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_NONE;
        }
    }

  return GRUB_ERR_EOF;
}

static grub_err_t
grub_verify_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize)
{
  grub_err_t err = GRUB_ERR_BAD_SIGNATURE, ret;
  grub_size_t datasize;
  grub_append_sig_t sig;
  grub_pkcs7_rcl_t rcl;

  if (!db.no_of_certs && !db.no_of_hashes)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "no trusted keys%s to verify against",
                       (append_key_mgmt == true ? "/hashes" : ""));

  ret = extract_appended_signature (buf, bufsize, &sig);
  if (ret != GRUB_ERR_NONE)
    return ret;

  append_sig_len = sig.signature_len;
  datasize = bufsize - sig.signature_len;

  /*
   * If signature verification is enabled with dynamic key management mode,
   * Verify binary hash against the db and dbx list.
   */
  if (append_key_mgmt == true)
    {
      err = verify_binary_hash (buf, datasize);
      if (err == GRUB_ERR_BAD_SIGNATURE)
        {
          grub_pkcs7_spec->release (&sig.pkcs7);
          return grub_error (err,
                             "failed to verify the binary hash against a trusted binary hash");
        }
    }

  /* Verify signature using trusted keys from db list. */
  if (db.no_of_certs > 0)
    {
      rcl.certs = dbx.certs;
      rcl.hashes = dbx.hashes;
      ret = grub_pkcs7_spec->verify (&sig.pkcs7, db.certs, &rcl, buf, datasize);
    }
  else
    ret = GRUB_ERR_FILE_NOT_FOUND;

   grub_pkcs7_spec->release (&sig.pkcs7);

   /*
    * If the signature verification succeeds or If binary hash verification
    * is successful and the singer key is not found in db and dbx.
    * Return with success. Otherwise, the return failed.
    */
   if (ret == GRUB_ERR_NONE ||
       (ret == GRUB_ERR_FILE_NOT_FOUND && err == GRUB_ERR_NONE))
     return GRUB_ERR_NONE;

  return grub_error (ret, "failed to verify signature against a trusted key");
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t signed_file;
  grub_err_t err;
  grub_uint8_t *signed_data = NULL;
  grub_size_t signed_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a signed file is expected\nExample:\n\tappend_verify <SIGNED FILE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing signed file");

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  signed_file = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (signed_file == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, "could not open %s file", args[0]);

  err = file_read_whole (signed_file, &signed_data, &signed_data_size);
  if (err == GRUB_ERR_NONE)
    {
      err = grub_verify_appended_signature (signed_data, signed_data_size);
      grub_free (signed_data);
    }

  grub_file_close (signed_file);

  return err;
}

/*
 * Checks the trusted certificate against dbx list if dynamic key management is
 * enabled. And add it to the db list if it is not already present.
 *
 * Note: When signature verification is enabled, this command only accepts the
 * trusted certificate that is signed with an appended signature.
 * The signature is verified by the appendedsig module. If verification succeeds,
 * the certificate is added to the db list. Otherwise, an error is posted and
 * the certificate is not added.
 * When signature verification is disabled, it accepts the trusted certificate
 * without an appended signature and add it to the db list.
 *
 * Also, note that the adding of the trusted certificate using this command does
 * not persist across reboots.
 */
static grub_err_t
grub_cmd_db_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a trusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_db_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing trusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual certificate size by subtracting the appended signature size from
   * the certificate size because the certificate has an appended signature, and
   * this actual certificate size is used to get the X.509 certificate.
   */
  if (check_sigs == true)
    cert_data_size -= append_sig_len;

  err = add_certificate (cert_data, cert_data_size, false, &db);
  grub_free (cert_data);

  return err;
}

/*
 * Add the distrusted certificate to the dbx list if not present when dynamic key
 * management is enabled. Remove the distrusted certificate from the db list and
 * will not add it to the dbx list when static key management is enabled
 *
 * Note: When signature verification is enabled, this command only accepts the
 * distrusted certificate that is signed with an appended signature.
 * The signature is verified by the appended sig module. If verification
 * succeeds, the certificate is removed from the db list. Otherwise, an error
 * is posted and the certificate is not removed.
 * When signature verification is disabled, it accepts the distrusted certificate
 * without an appended signature and removes it from the db list.
 *
 * Also, note that the adding of the distrusted certificate using this command
 * does not persist across reboots.
 */
static grub_err_t
grub_cmd_dbx_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a distrusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_dbx_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing distrusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual certificate size by subtracting the appended signature size from
   * the certificate size because the certificate has an appended signature, and
   * this actual certificate size is used to get the X.509 certificate.
   */
  if (check_sigs == true)
    cert_data_size -= append_sig_len;

  /* Only add the certificate to the dbx list if dynamic key management is enabled. */
  if (append_key_mgmt == true)
    err = add_certificate (cert_data, cert_data_size, false, &dbx);
  else
    {
      /* Remove distrusted certificate from the db list if present. */
      err = remove_cert_from_db (cert_data, cert_data_size);
      if (err != GRUB_ERR_NONE)
        {
          grub_free (cert_data);
          return err;
        }
    }

  grub_free (cert_data);

  return err;
}

static grub_err_t
grub_cmd_list_db (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
                  char **args __attribute__ ((unused)))
{
  grub_hash_t *curr_hash;
  grub_uint32_t i = 0;

  grub_x509_spec->print (db.certs);

  if (append_key_mgmt == false)
    return GRUB_ERR_NONE;

  for (curr_hash = db.hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    {
      grub_printf ("\nBinary hash: %u\n", i + 1);
      grub_printf ("    Hash: sha%" PRIuGRUB_SIZE "\n         ", curr_hash->hash_size * 8);
      grub_util_hexdump_colon (curr_hash->hash, curr_hash->hash_size);
      i++;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list_dbx (grub_command_t cmd __attribute__((unused)),
                   int argc __attribute__((unused)), char **args __attribute__((unused)))
{
  grub_hash_t *curr_hash;
  grub_uint32_t i = 0;

  if (append_key_mgmt == false)
    return grub_error (GRUB_ERR_ACCESS_DENIED,
                       "append_list_dbx command is unsupported in static key mode");

  grub_x509_spec->print (dbx.certs);

  for (curr_hash = dbx.hashes; curr_hash != NULL; curr_hash = curr_hash->next)
    {
      grub_printf ("\nCertificate/Binary hash: %u\n", i + 1);
      grub_printf ("    hash: sha%" PRIuGRUB_SIZE "\n         ",
                   curr_hash->hash_size * 8);
      grub_util_hexdump_colon (curr_hash->hash, curr_hash->hash_size);
      i++;
    }

  return GRUB_ERR_NONE;
}

/*
 * Checks the trusted binary hash against dbx list and add them to the db list if
 * it is not already present.
 *
 * Note: When signature verification is enabled, this command only accepts the
 * binary hash file that is signed with an appended signature. The signature is
 * verified by the appendedsig module. If verification succeeds, the binary hash
 * is added to the db list. Otherwise, an error is posted and the binary hash is
 * not added.
 * When signature verification is disabled, it accepts the binary hash file
 * without an appended signature and adds it to the db list.
 *
 * Also, note that the adding of the trusted binary hash using this command does
 * not persist across reboots.
 */
static grub_err_t
grub_cmd_add_db_hash (grub_command_t cmd __attribute__((unused)), int argc, char**args)
{
  grub_err_t rc;
  grub_file_t hash_file;
  grub_uint8_t *hash_data = NULL;
  grub_size_t hash_data_size = 0;

  if (append_key_mgmt == false)
    return grub_error (GRUB_ERR_ACCESS_DENIED,
                       "append_add_db_hash command is unsupported in static key mode");

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a trusted binary hash file is expected in binary format\n"
                       "Example:\n\tappend_add_db_hash <BINARY HASH FILE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing trusted binary hash file");

  hash_file = grub_file_open (args[0], GRUB_FILE_TYPE_HASH_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (hash_file == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, "unable to open %s file", args[0]);

  rc = file_read_whole (hash_file, &hash_data, &hash_data_size);
  grub_file_close (hash_file);
  if (rc != GRUB_ERR_NONE)
    return rc;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual hash data size by subtracting the appended signature size from
   * the hash data size because the hash has an appended signature, and this
   * actual hash data size is used to get the hash data.
   */
  if (check_sigs == true)
    hash_data_size -= append_sig_len;

  grub_dprintf ("appendedsig",
                "adding a trusted binary hash %02x%02x%02x%02x... with size of %" PRIuGRUB_SIZE "\n",
                hash_data[0], hash_data[1], hash_data[2], hash_data[3], hash_data_size);

  /* Only accept SHA256, SHA384 and SHA512 binary hash */
  if (hash_data_size != SHA256_HASH_SIZE && hash_data_size != SHA384_HASH_SIZE &&
      hash_data_size != SHA512_HASH_SIZE)
    {
      grub_free (hash_data);
      return grub_error (GRUB_ERR_BAD_SIGNATURE, "unacceptable trusted binary hash type");
    }

  rc = add_hash (hash_data, hash_data_size, false, &db);
  grub_free (hash_data);

  return rc;
}

/*
 * Add the distrusted binary/certificate hash to the dbx if it is not already present.
 *
 * Note: When signature verification is enabled, this command only accepts the
 * binary/certificate hash file that is signed with an appended signature. The
 * signature is verified by the appendedsig module. If verification succeeds,
 * the binary/certificate hash is added to the dbx list. Otherwise, an error is
 * posted and the binary/certificate hash is not added.
 * When signature verification is disabled, it accepts the binary/certificate
 * hash file without an appended signature and adds it to the dbx list.
 *
 * Also, note that the adding of the distrusted binary/certificate hash using
 * this command does not persist across reboots.
 */
static grub_err_t
grub_cmd_add_dbx_hash (grub_extcmd_context_t ctxt, int argc __attribute__ ((unused)),
                       char **args __attribute__ ((unused)))
{
  grub_err_t rc;
  grub_file_t hash_file;
  grub_uint8_t *hash_data = NULL;
  grub_size_t hash_data_size = 0;
  char *file_path;

  if (append_key_mgmt == false)
    return grub_error (GRUB_ERR_ACCESS_DENIED,
                       "append_add_dbx_hash command is unsupported in static key mode");

  if (!ctxt->state[OPTION_BINARY_HASH].set && !ctxt->state[OPTION_CERT_HASH].set)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a distrusted certificate/binary hash file is expected in binary format\n"
                       "Example:\n\tappend_add_dbx_hash [option] <FILE>\n"
                       "option:\n[-b|--binary-hash] FILE [BINARY HASH FILE]\n"
                       "[-c|--cert-hash] FILE [CERTFICATE HASH FILE]\n");

  if (ctxt->state[OPTION_BINARY_HASH].arg == NULL && ctxt->state[OPTION_CERT_HASH].arg == NULL)
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing distrusted certificate/binary hash file");

  if (ctxt->state[OPTION_BINARY_HASH].arg != NULL)
    file_path = ctxt->state[OPTION_BINARY_HASH].arg;
  else
    file_path = ctxt->state[OPTION_CERT_HASH].arg;

  hash_file = grub_file_open (file_path, GRUB_FILE_TYPE_HASH_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (hash_file == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, "unable to open %s file", file_path);

  rc = file_read_whole (hash_file, &hash_data, &hash_data_size);
  grub_file_close (hash_file);
  if (rc != GRUB_ERR_NONE)
    return rc;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual hash data size by subtracting the appended signature size from
   * the hash data size because the hash has an appended signature, and this
   * actual hash data size is used to get the hash data.
   */
  if (check_sigs == true)
    hash_data_size -= append_sig_len;

  grub_dprintf ("appendedsig",
                "adding a distrusted certificate/binary hash %02x%02x%02x%02x..."
                " with size of %" PRIuGRUB_SIZE "\n", hash_data[0], hash_data[1],
                hash_data[2], hash_data[3], hash_data_size);

  if (ctxt->state[OPTION_BINARY_HASH].set || ctxt->state[OPTION_CERT_HASH].set)
    {
      /* Only accept SHA256, SHA384 and SHA512 certificate/binary hash */
      if (hash_data_size != SHA256_HASH_SIZE && hash_data_size != SHA384_HASH_SIZE &&
          hash_data_size != SHA512_HASH_SIZE)
        {
          grub_free (hash_data);
          return grub_error (GRUB_ERR_BAD_SIGNATURE,
                             "unacceptable distrusted certificate/binary hash type");
        }
    }

  rc = add_hash (hash_data, hash_data_size, false, &dbx);
  grub_free (hash_data);

  return rc;
}

#if !defined(GRUB_MACHINE_EMU)
/* Add the X.509 certificates/binary hash to the db list from PKS. */
static grub_err_t
load_pks2db (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < pks_keystore->db_entries; i++)
    {
      if (is_hash (&pks_keystore->db[i].guid) == true)
        {
          rc = add_hash (pks_keystore->db[i].data,
                         pks_keystore->db[i].data_size, true, &db);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_x509 (&pks_keystore->db[i].guid) == true)
        {
          rc = add_certificate (pks_keystore->db[i].data,
                                pks_keystore->db[i].data_size, true, &db);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/* Add the certificates and certificate/binary hash to the dbx list from PKS. */
static grub_err_t
load_pks2dbx (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < pks_keystore->dbx_entries; i++)
    {
      if (is_x509 (&pks_keystore->dbx[i].guid) == true)
        {
          rc = add_certificate (pks_keystore->dbx[i].data,
                                pks_keystore->dbx[i].data_size, true, &dbx);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_hash (&pks_keystore->dbx[i].guid) == true)
        {
          rc = add_hash (pks_keystore->dbx[i].data,
                         pks_keystore->dbx[i].data_size, true, &dbx);
          if (rc != GRUB_ERR_NONE)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}
#endif

/*
 * Extract the X.509 certificates from the ELF Note header, parse it, and add
 * it to the db list.
 */
static void
load_elf2db (void)
{
  grub_err_t err;
  struct grub_module_header *header;
  struct grub_file pseudo_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  FOR_MODULES (header)
    {
      /* Not an X.509 certificate, skip. */
      if (header->type != OBJ_TYPE_X509_PUBKEY)
        continue;

      grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
      pseudo_file.fs = &pseudo_fs;
      pseudo_file.size = header->size - sizeof (struct grub_module_header);
      pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

      grub_dprintf ("appendedsig", "found an X.509 certificate, size=%" PRIuGRUB_UINT64_T "\n",
                    pseudo_file.size);

      err = file_read_whole (&pseudo_file, &cert_data, &cert_data_size);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
      else if (err != GRUB_ERR_NONE)
        continue;

      err = add_certificate (cert_data, cert_data_size, true, &db);
      grub_free (cert_data);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
    }
}

/*
 * Extract trusted and distrusted keys from PKS and store them in the db and
 * dbx list.
 */
static void
create_dbs_from_pks (void)
{
#if !defined(GRUB_MACHINE_EMU)
  grub_err_t err;

  err = load_pks2dbx ();
  if (err != GRUB_ERR_NONE)
    grub_printf ("warning: dbx list might not be fully populated\n");

  /*
   * If db does not exist in the PKS storage, then read the static keys as a db
   * default keys from the GRUB ELF Note and add them into the db list.
   */
  if (pks_keystore->db_exists == false)
    load_elf2db ();
  else
    {
      err = load_pks2db ();
      if (err != GRUB_ERR_NONE)
        grub_printf ("warning: db list might not be fully populated\n");
    }

  grub_pks_free_data ();
  grub_dprintf ("appendedsig", "the db list now has %u keys\n"
                "the dbx list now has %u keys\n",
                db.no_of_hashes + db.no_of_certs,
                dbx.no_of_hashes + dbx.no_of_certs);
#endif
}

/* Free db list memory */
static void
free_db_list (void)
{
  grub_x509_cert_t *cert;
  grub_hash_t *curr_hash;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      grub_x509_spec->release (cert);
      grub_x509_spec->free (cert);
    }

  while (db.hashes != NULL)
    {
      curr_hash = db.hashes;
      db.hashes = db.hashes->next;
      grub_free (curr_hash->hash);
      grub_free (curr_hash);
    }

  grub_memset (&db, 0, sizeof (grub_append_sd_t));
}

/* Free dbx list memory */
static void
free_dbx_list (void)
{
  grub_x509_cert_t *cert;
  grub_hash_t *curr_hash;

  while (dbx.certs != NULL)
    {
      cert = dbx.certs;
      dbx.certs = dbx.certs->next;
      grub_x509_spec->release (cert);
      grub_x509_spec->free (cert);
    }

  while (dbx.hashes != NULL)
    {
      curr_hash = dbx.hashes;
      dbx.hashes = dbx.hashes->next;
      grub_free (curr_hash->hash);
      grub_free (curr_hash);
    }

  grub_memset (&dbx, 0, sizeof (grub_append_sd_t));
}

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                   const char *val __attribute__ ((unused)))
{
  if (check_sigs == true)
    return "yes";

  return "no";
}

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed if signature verification is enabled
   * (check_sigs is set to true) and GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup ("yes");
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string enforce");

      return ret;
    }

  if (grub_strcmp (val, "yes") == 0)
    check_sigs = true;
  else if (grub_strcmp (val, "no") == 0)
    check_sigs = false;

  ret = grub_strdup (grub_env_read_sec (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string %s",
                grub_env_read_sec (NULL, NULL));

  return ret;
}

static const char *
grub_env_read_key_mgmt (struct grub_env_var *var __attribute__ ((unused)),
                        const char *val __attribute__ ((unused)))
{
  if (append_key_mgmt == true)
    return "dynamic";

  return "static";
}

static char *
grub_env_write_key_mgmt (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed if signature verification is enabled
   * (check_sigs is set to true) and GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

      return ret;
    }

  if (grub_strcmp (val, "dynamic") == 0)
    append_key_mgmt = true;
  else if (grub_strcmp (val, "static") == 0)
    append_key_mgmt = false;

  ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  return ret;
}

static grub_err_t
appendedsig_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
                  void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  if (check_sigs == false)
    {
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }

  switch (type & GRUB_FILE_TYPE_MASK)
    {
      case GRUB_FILE_TYPE_CERTIFICATE_TRUST:
        /*
         * This is a certificate to add to trusted keychain.
         *
         * This needs to be verified or blocked. Ideally we'd write an x509
         * verifier, but we lack the hubris required to take this on. Instead,
         * require that it have an appended signature.
         */
      case GRUB_FILE_TYPE_HASH_TRUST:
        /*
         * This is a certificate/binary hash to add to db/dbx. This needs to be
         * verified or blocked.
         */
      case GRUB_FILE_TYPE_LINUX_KERNEL:
      case GRUB_FILE_TYPE_GRUB_MODULE:
        /*
         * Appended signatures are only defined for ELF binaries. Out of an
         * abundance of caution, we only verify Linux kernels and GRUB modules
         * at this point.
         */
        *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
        return GRUB_ERR_NONE;

      case GRUB_FILE_TYPE_ACPI_TABLE:
      case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
        /*
         * It is possible to use appended signature verification without
         * lockdown - like the PGP verifier. When combined with an embedded
         * config file in a signed GRUB binary, this could still be a meaningful
         * secure-boot chain - so long as it isn't subverted by something like a
         * rouge ACPI table or DT image. Defer them explicitly.
         */
        *flags = GRUB_VERIFY_FLAGS_DEFER_AUTH;
        return GRUB_ERR_NONE;

      default:
        *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
        return GRUB_ERR_NONE;
    }
}

static grub_err_t
appendedsig_write (void *ctxt __attribute__ ((unused)), void *buf, grub_size_t size)
{
  return grub_verify_appended_signature (buf, size);
}

struct grub_file_verifier grub_appendedsig_verifier = {
  .name = "appendedsig",
  .init = appendedsig_init,
  .write = appendedsig_write,
};

static grub_command_t cmd_verify, cmd_list_db, cmd_dbx_cert, cmd_db_cert;
static grub_command_t cmd_list_dbx, cmd_db_hash;
static grub_extcmd_t cmd_dbx_hash;

GRUB_MOD_INIT (appendedsig)
{
  grub_int32_t rc;

  /*
   * If secure boot is enabled with enforce mode and GRUB is locked down, enable
   * signature verification.
   */
  if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    check_sigs = true;

#if !defined(GRUB_MACHINE_EMU)
  /* If PKS keystore is available, use dynamic key management. */
  pks_keystore = grub_pks_get_keystore ();
  if (pks_keystore != NULL)
    append_key_mgmt = true;
#endif

  /*
   * This is appended signature verification environment variable. It is
   * automatically set to either "no" or "yes" based on the ’ibm,secure-boot’
   * device tree property.
   *
   * "no": No signature verification. This is the default.
   *
   * "yes": Enforce signature verification. When GRUB is locked down, user cannot
   *        change the value by setting the check_appended_signatures variable
   *        back to ‘no’
   */
  grub_register_variable_hook ("check_appended_signatures", grub_env_read_sec, grub_env_write_sec);
  grub_env_export ("check_appended_signatures");

  /*
   * This is appended signature key management environment variable. It is
   * automatically set to either "static" or "dynamic" based on the
   * Platform KeyStore.
   *
   * "static": Enforce static key management signature verification. This is
   *           the default. When the GRUB is locked down, user cannot change
   *           the value by setting the appendedsig_key_mgmt variable back to
   *           "dynamic".
   *
   * "dynamic": Enforce dynamic key management signature verification. When the
   *            GRUB is locked down, user cannot change the value by setting the
   *            appendedsig_key_mgmt variable back to "static".
   */
  grub_register_variable_hook ("appendedsig_key_mgmt", grub_env_read_key_mgmt, grub_env_write_key_mgmt);
  grub_env_export ("appendedsig_key_mgmt");

  rc = grub_asn1_init ();
  if (rc != ASN1_SUCCESS)
    grub_fatal ("error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  /*
   * If signature verification is enabled with the dynamic key management,
   * extract trusted and distrusted keys from PKS and store them in the db
   * and dbx list.
   */
  if (append_key_mgmt == true)
    create_dbs_from_pks ();
  /*
   * If signature verification is enabled with the static key management,
   * extract trusted keys from ELF Note and store them in the db list.
   */
  else
    {
      load_elf2db ();
      grub_dprintf ("appendedsig", "the db list now has %u static keys\n",
                    db.no_of_certs);
    }

  cmd_verify = grub_register_command ("append_verify", grub_cmd_verify_signature, N_("<SIGNED_FILE>"),
                                      N_("Verify SIGNED_FILE against the trusted X.509 certificates in the db list"));
  cmd_list_db = grub_register_command ("append_list_db", grub_cmd_list_db, 0,
                                       N_("Show the list of trusted X.509 certificates from the db list"));
  cmd_db_cert = grub_register_command ("append_add_db_cert", grub_cmd_db_cert, N_("<X509_CERTIFICATE>"),
                                       N_("Add trusted X509_CERTIFICATE to the db list"));
  cmd_dbx_cert = grub_register_command ("append_add_dbx_cert", grub_cmd_dbx_cert, N_("<X509_CERTIFICATE>"),
                                        N_("Add distrusted X509_CERTIFICATE to the dbx list"));

  cmd_list_dbx = grub_register_command ("append_list_dbx", grub_cmd_list_dbx, 0,
                                        N_("Show the list of distrusted certificates and"
                                        " certificate/binary hashes from the dbx list"));
  cmd_db_hash = grub_register_command ("append_add_db_hash", grub_cmd_add_db_hash, N_("BINARY HASH FILE"),
                                       N_("Add trusted BINARY HASH to the db list."));
  cmd_dbx_hash = grub_register_extcmd ("append_add_dbx_hash", grub_cmd_add_dbx_hash, 0,
                                       N_("[-b|--binary-hash] FILE [BINARY HASH FILE]\n"
                                       "[-c|--cert-hash] FILE [CERTFICATE HASH FILE]"),
                                       N_("Add distrusted CERTFICATE/BINARY HASH to the dbx list."), options);

  grub_verifier_register (&grub_appendedsig_verifier);
  grub_dl_set_persistent (mod);
}

GRUB_MOD_FINI (appendedsig)
{
  /*
   * grub_dl_set_persistent should prevent this from actually running, but it
   * does still run under emu.
   */

  free_db_list ();
  free_dbx_list ();
  grub_register_variable_hook ("check_appended_signatures", NULL, NULL);
  grub_env_unset ("check_appended_signatures");
  grub_register_variable_hook ("appendedsig_key_mgmt", NULL, NULL);
  grub_env_unset ("appendedsig_key_mgmt");
  grub_verifier_unregister (&grub_appendedsig_verifier);
  grub_unregister_command (cmd_verify);
  grub_unregister_command (cmd_list_db);
  grub_unregister_command (cmd_db_cert);
  grub_unregister_command (cmd_dbx_cert);
  grub_unregister_command (cmd_list_dbx);
  grub_unregister_command (cmd_db_hash);
  grub_unregister_extcmd (cmd_dbx_hash);
}
