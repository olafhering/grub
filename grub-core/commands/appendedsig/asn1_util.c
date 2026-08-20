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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/gcrypt/gcrypt.h>

#include "asn1_util.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

asn1_node grub_gnutls_gnutls_asn = NULL;
asn1_node grub_gnutls_pkix_asn = NULL;

extern const asn1_static_node grub_gnutls_asn1_tab[];
extern const asn1_static_node grub_pkix_asn1_tab[];

static const char *dir_utf8str = "utf8String";
static const char *dir_printablestr = "printableString";
static const grub_int32_t dir_utf8str_len = 10;
static const grub_int32_t dir_printablestr_len = 15;

/* Convert a two-character numeric string slice into an integer */
static grub_int32_t
asn1_str2digit (const char *str)
{
  return (str[0] - '0') * 10 + (str[1] - '0');
}

static grub_uint8_t
asn1_days_in_month (grub_uint16_t year, grub_uint8_t month)
{
  static const grub_uint8_t days[] = { 31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31 };

  /* Handle leap year adjustment for February. */
  if (month == 2 &&
      (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0))
    return 29;

  return days[month - 1];
}

/* Converts ASN1 time to datetime. */
grub_err_t
grub_asn1_decode_datetime (const char *time_str, const grub_int32_t len,
                           grub_int64_t *timestamp)
{
  struct grub_datetime dt = { 0 };
  grub_int64_t ts = 0;

  if (time_str == NULL || len <= 0 || timestamp == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  *timestamp = 0;

  if (len == 13 && time_str[12] == 'Z') /* UTCTime: YYMMDDHHMMSSZ */
    {
      grub_int32_t year = asn1_str2digit (time_str);
      dt.year = (year < 50) ? (2000 + year) : (1900 + year);
      time_str += 2;
    }
  else if (len == 15 && time_str[14] == 'Z') /* GeneralizedTime: YYYYMMDDHHMMSSZ */
    {
      dt.year = asn1_str2digit (time_str) * 100 + asn1_str2digit (time_str + 2);
      time_str += 4;
    }
  else
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "Unsupported ASN.1 time format");

  /* Parse remaining identical chunks. */
  dt.month  = asn1_str2digit (time_str);
  dt.day    = asn1_str2digit (time_str + 2);
  dt.hour   = asn1_str2digit (time_str + 4);
  dt.minute = asn1_str2digit (time_str + 6);
  dt.second = asn1_str2digit (time_str + 8);

  /* Simple range validating bounds. */
  if (dt.month < 1 || dt.month > 12 || dt.day < 1 ||
      dt.day > asn1_days_in_month (dt.year, dt.month) ||
      dt.hour > 23 || dt.minute > 59 || dt.second > 60)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "Invalid datetime values parsed");

  if (!grub_datetime2unixtime (&dt, &ts))
    return grub_error (GRUB_ERR_BAD_NUMBER, "failed to get unix time");

  *timestamp = ts;

  return GRUB_ERR_NONE;
}

/* Decode a string as defined in Appendix A. */
static grub_err_t
asn1_decode_string (char *der, grub_int32_t der_size, char **string, grub_int32_t *string_size)
{
  asn1_node strasn;
  grub_int32_t rc;
  char *choice;
  grub_int32_t choice_size = 0;
  grub_int32_t tmp_size = 0;
  grub_err_t err = GRUB_ERR_NONE;

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.DirectoryString", &strasn);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for DirectoryString: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&strasn, der, &der_size, ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "could not parse DER for DirectoryString: %s", asn1_error);
      goto cleanup;
    }

  choice = grub_asn1_allocate_and_read (strasn, "", "DirectoryString choice", &choice_size);
  if (choice == NULL)
    {
      err = grub_errno;
      goto cleanup;
    }

  if (dir_utf8str_len == choice_size - 1 &&
      grub_strncmp (dir_utf8str, choice, choice_size) == 0)
    {
      rc = asn1_read_value (strasn, dir_utf8str, NULL, &tmp_size);
      if (rc != ASN1_MEM_ERROR || tmp_size == 0)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of UTF-8 string: %s",
                            ((rc != ASN1_MEM_ERROR) ? asn1_strerror (rc) : "contains zero bytes"));
          goto cleanup_choice;
        }
    }
  else if (dir_printablestr_len == choice_size - 1 &&
           grub_strncmp (dir_printablestr, choice, choice_size) == 0)
    {
      rc = asn1_read_value (strasn, dir_printablestr, NULL, &tmp_size);
      if (rc != ASN1_MEM_ERROR || tmp_size == 0)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of printableString: %s",
                            ((rc != ASN1_MEM_ERROR) ? asn1_strerror (rc) : "contains zero bytes"));
          goto cleanup_choice;
        }
    }
  else
    {
      err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                        "only UTF-8 and printable DirectoryStrings are supported, got %s",
                        choice);
      goto cleanup_choice;
    }

  /* Read size does not include trailing NUL. */
  tmp_size++;

  *string = grub_malloc (tmp_size);
  if (*string == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                        "cannot allocate memory for DirectoryString contents");
      goto cleanup_choice;
    }

  rc = asn1_read_value (strasn, choice, *string, &tmp_size);
  if (rc != ASN1_SUCCESS || tmp_size == 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading out %s in DirectoryString: %s",
                        choice, ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
      grub_free (*string);
      *string = NULL;
      goto cleanup_choice;
    }

  *string_size = tmp_size + 1;
  (*string)[tmp_size] = '\0';

 cleanup_choice:
  grub_free (choice);
 cleanup:
  asn1_delete_structure (&strasn);

  return err;
}

grub_err_t
grub_asn1_read_rnd_sequence (asn1_node cert_asn1, const char *root_path, const char *oid,
                             const grub_int32_t oid_len, char **name, grub_int32_t *name_size)
{
  grub_int32_t seq_components, set_components;
  grub_int32_t rc;
  grub_int32_t i, j;
  char *top_path, *set_path, *type_path, *val_path;
  char type[GRUB_MAX_OID_LEN];
  grub_int32_t type_len = sizeof (type);
  grub_int32_t string_size = 0;
  char *string_der;
  grub_err_t ret;

  if (cert_asn1 == NULL || root_path == NULL || oid == NULL ||
      name == NULL || name_size == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  *name = NULL;

  top_path = grub_xasprintf ("%s.rdnSequence", root_path);
  if (top_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate memory for %s name parsing path", root_path);

  rc = asn1_number_of_elements (cert_asn1, top_path, &seq_components);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting name components: %s",
                        asn1_strerror (rc));
      goto cleanup;
    }

  for (i = 1; i <= seq_components; i++)
    {
      set_path = grub_xasprintf ("%s.?%d", top_path, i);
      if (set_path == NULL)
        {
          ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                            "could not allocate memory for %s name set parsing path",
                            root_path);
          goto cleanup_set;
        }
      /* This brings us, hopefully, to a set. */
      rc = asn1_number_of_elements (cert_asn1, set_path, &set_components);
      if (rc != ASN1_SUCCESS)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                            "error counting name sub-components components (element %d): %s",
                            i, asn1_strerror (rc));
          goto cleanup_set;
        }
      for (j = 1; j <= set_components; j++)
        {
          type_path = grub_xasprintf ("%s.?%d.?%d.type", top_path, i, j);
          if (type_path == NULL)
            {
              ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                                "could not allocate memory for %s name component type path",
                                root_path);
              goto cleanup_set;
            }
          type_len = sizeof (type);
          rc = asn1_read_value (cert_asn1, type_path, type, &type_len);
          if (rc != ASN1_SUCCESS || type_len == 0)
            {
              ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading %s name component type: %s",
                                root_path,
                                ((rc != ASN1_SUCCESS) ? asn1_strerror (rc) : "contains zero bytes"));
              goto cleanup_type;
            }

          if (oid_len != type_len - 1 || grub_strncmp (type, oid, type_len) != 0)
            {
              grub_free (type_path);
              continue;
            }

          val_path = grub_xasprintf ("%s.?%d.?%d.value", top_path, i, j);
          if (val_path == NULL)
            {
              ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                                "could not allocate memory for %s name component value path",
                                root_path);
              goto cleanup_type;
            }

          string_der = grub_asn1_allocate_and_read (cert_asn1, val_path, root_path, &string_size);
          if (string_der == NULL)
            {
              ret = grub_errno;
              goto cleanup_val_path;
            }

          ret = asn1_decode_string (string_der, string_size, name, name_size);
          if (ret)
            goto cleanup_string;

          grub_free (string_der);
          grub_free (type_path);
          grub_free (val_path);
          break;
        }

      grub_free (set_path);
      if (*name)
        break;
    }

  grub_free (top_path);

  return GRUB_ERR_NONE;

 cleanup_string:
  grub_free (string_der);
 cleanup_val_path:
  grub_free (val_path);
 cleanup_type:
  grub_free (type_path);
 cleanup_set:
  grub_free (set_path);
 cleanup:
  grub_free (top_path);

  return ret;
}

/*
 * Read a value from an ASN1 node, allocating memory to store it. It will work
 * for anything where the size libtasn1 returns is right:
 *  - Integers
 *  - Octet strings
 *  - DER encoding of other structures
 *
 * It will _not_ work for things where libtasn1 size requires adjustment:
 *  - Strings that require an extra NULL byte at the end
 *  - Bit strings because libtasn1 returns the length in bits, not bytes.
 *
 * If the function returns a non-NULL value, the caller must free it.
 */
void *
grub_asn1_allocate_and_read (asn1_node node, const char *name, const char *friendly_name,
                             grub_int32_t *content_size)
{
  grub_int32_t result;
  grub_uint8_t *tmpstr = NULL;
  grub_int32_t tmpstr_size = 0;

  if (node == NULL || name == NULL || friendly_name == NULL || content_size == NULL)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");
      return NULL;
    }

  result = asn1_read_value (node, name, NULL, &tmpstr_size);
  if (result != ASN1_MEM_ERROR || tmpstr_size == 0)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of %s: %s",
                  friendly_name,
                  ((result != ASN1_MEM_ERROR) ? asn1_strerror (result) : "contains zero bytes"));
      return NULL;
    }

  tmpstr = grub_malloc (tmpstr_size);
  if (tmpstr == NULL)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not allocate memory to store %s",
                  friendly_name) ;
      return NULL;
    }

  result = asn1_read_value (node, name, tmpstr, &tmpstr_size);
  if (result != ASN1_SUCCESS || tmpstr_size == 0)
    {
      grub_free (tmpstr);
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading %s: %s", friendly_name,
                  ((result != ASN1_SUCCESS) ? asn1_strerror (result) : "contains zero bytes"));
      return NULL;
    }

  *content_size = tmpstr_size;

  return tmpstr;
}

int
grub_asn1_init (void)
{
  int res;

  res = asn1_array2tree (grub_gnutls_asn1_tab, &grub_gnutls_gnutls_asn, NULL);
  if (res != ASN1_SUCCESS)
    return res;

  res = asn1_array2tree (grub_pkix_asn1_tab, &grub_gnutls_pkix_asn, NULL);

  return res;
}
