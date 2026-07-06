/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025 Free Software Foundation, Inc.
 *  Copyright (C) 2026 IBM Corporation
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

#include <grub/test.h>
#include <grub/crypto.h>
#include <grub/gcrypt/gcrypt.h>

#include "testdata/messages.h"
#include "testdata/contexts.h"
#include "testdata/pubkeys.h"
#include "testdata/signatures.h"

GRUB_MOD_LICENSE ("GPLv3+");

extern gcry_pk_spec_t _gcry_pubkey_spec_mldsa;

static void
mldsa_raw_test (const enum gcry_mldsa_algos algo, const grub_uint8_t *pubkey,
                const grub_uint32_t pubkey_len, const grub_uint8_t *signature,
                const grub_uint32_t signature_len, const bool with_ctx)
{
  gcry_sexp_t s_sig, s_pubkey, s_tpubkey;
  grub_size_t errof;
  gpg_err_code_t rc;

  rc = _gcry_sexp_build (&s_pubkey, &errof, "(%s(p%b))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
			 pubkey_len, pubkey, NULL);
  grub_test_assert (rc == 0, "pub-key sexp build failed");

  rc = _gcry_sexp_build (&s_sig, &errof, "(sig-val(%s(s%b)))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
                         signature_len, signature, NULL);
  grub_test_assert (rc == 0, "signature sexp build failed");

  if (with_ctx)
    {
      rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_pubkey, large_msg, large_msg_len,
		                               ctx, ctx_len);
      grub_test_assert (rc == 0, "raw_verify: %s signature verification failed: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
      /* Tampered message test */
      rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_pubkey, msg_tamp, msg_tamp_len,
		                               ctx, ctx_len);
      grub_test_assert (rc != 0, "raw_verify: %s signature verification succeeded wrongly "
                             "with tampered message: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
    }
  else
    {
      rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_pubkey, large_msg,
                                               large_msg_len, NULL, 0);
      grub_test_assert (rc == 0, "raw_verify: %s signature verification failed: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
      /* Tampered message test */
      rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_pubkey, msg_tamp, msg_tamp_len,
		                               NULL, 0);
      grub_test_assert (rc != 0, "raw_verify: %s signature verification succeeded wrongly "
                             "with tampered message: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
    }

  /* Tampered context string test */
  if (with_ctx)
    {
      rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_pubkey, large_msg, large_msg_len,
                                               ctx_tamp, ctx_tamp_len);
      grub_test_assert (rc != 0, "raw_verify: %s signature verification succeeded wrongly "
                                 "with tampered context string: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
    }

  /* Tampered public key test */
  rc = _gcry_sexp_build (&s_tpubkey, &errof, "(%s(p%b))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
			 tamp_pub_key_len, tamp_pub_key, NULL);
  grub_test_assert (rc == 0, "Tampered pub-key sexp build failed");

  rc = _gcry_pubkey_spec_mldsa.raw_verify (s_sig, s_tpubkey, large_msg, large_msg_len, NULL, 0);
  grub_test_assert (rc != 0, "raw_verify: %s signature verification succeeded wrongly "
                             "with tampered publioc key: %d",
                    _gcry_pubkey_spec_mldsa.aliases[algo], rc);

  _gcry_sexp_release (s_sig);
  _gcry_sexp_release (s_pubkey);
  _gcry_sexp_release (s_tpubkey);
}

static void
mldsa_sexp_test (const enum gcry_mldsa_algos algo, const grub_uint8_t *pubkey,
                 const grub_uint32_t pubkey_len, const grub_uint8_t *signature,
                 const grub_uint32_t signature_len, const bool with_ctx)
{
  gcry_sexp_t s_sig, s_data, s_tdata, s_pubkey, s_tpubkey;
  grub_size_t errof;
  gpg_err_code_t rc;

  if (with_ctx)
    rc = _gcry_sexp_build (&s_data, &errof,
                           "(data(flags raw)(value %b)(label%b))",
                           msg_len, msg, ctx_len, ctx, NULL);
  else
    rc = _gcry_sexp_build (&s_data, &errof,
                           "(data(flags raw no-prefix)(value%b))",
                           msg_len, msg, NULL);

  grub_test_assert (rc == GPG_ERR_NO_ERROR, "data sexp build failed");

  rc = _gcry_sexp_build (&s_pubkey, &errof, "(%s(p%b))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
			 pubkey_len, pubkey, NULL);
  grub_test_assert (rc == 0, "pub-key sexp build failed");

  rc = _gcry_sexp_build (&s_sig, &errof, "(sig-val(%s(s%b)))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
                         signature_len, signature, NULL);
  grub_test_assert (rc == 0, "signature sexp build failed");

  rc = _gcry_pubkey_spec_mldsa.verify (s_sig, s_data, s_pubkey);
  grub_test_assert (rc == 0, "verify: %s signature verification failed: %d",
                    _gcry_pubkey_spec_mldsa.aliases[algo], rc);

  /* Tampered message test */
  if (with_ctx)
    rc = _gcry_sexp_build (&s_tdata, &errof,
                           "(data(flags raw)(value %b)(label%b))",
                           msg_tamp_len, msg_tamp, ctx_len, ctx, NULL);
  else
    rc = _gcry_sexp_build (&s_tdata, &errof,
                           "(data(flags raw no-prefix)(value%b))",
                           msg_tamp_len, msg_tamp, NULL);
  grub_test_assert (rc == 0,
                    "tampered data with context string sexp build failed");

  rc = _gcry_pubkey_spec_mldsa.verify (s_sig, s_tdata, s_pubkey);
  grub_test_assert (rc != 0, "verify: %s signature verification succeeded wrongly "
                             "with tampered message: %d",
                    _gcry_pubkey_spec_mldsa.aliases[algo], rc);

  /* Tampered context string test */
  if (with_ctx)
    {
      rc = _gcry_sexp_build (&s_tdata, &errof,
                             "(data(flags raw)(value %b)(label%b))",
                             msg_len, msg, ctx_tamp_len, ctx_tamp, NULL);
      grub_test_assert (rc == 0,
                        "tampered context string with data sexp build failed");

      rc = _gcry_pubkey_spec_mldsa.verify (s_sig, s_tdata, s_pubkey);
      grub_test_assert (rc != 0, "verify: %s signature verification succeeded wrongly "
                                 "with tampered context string: %d",
                        _gcry_pubkey_spec_mldsa.aliases[algo], rc);
    }

  /* Tampered public key test */
  rc = _gcry_sexp_build (&s_tpubkey, &errof, "(%s(p%b))",
                         _gcry_pubkey_spec_mldsa.aliases[algo],
			 tamp_pub_key_len, tamp_pub_key, NULL);
  grub_test_assert (rc == 0, "Tampered pub-key sexp build failed");

  rc = _gcry_pubkey_spec_mldsa.verify (s_sig, s_data, s_tpubkey);
  grub_test_assert (rc != 0, "verify: %s signature verification succeeded wrongly "
                             "with tampered publioc key: %d",
                    _gcry_pubkey_spec_mldsa.aliases[algo], rc);

  _gcry_sexp_release (s_sig);
  _gcry_sexp_release (s_data);
  _gcry_sexp_release (s_tdata);
  _gcry_sexp_release (s_tpubkey);
  _gcry_sexp_release (s_pubkey);
}

static void
mldsa_test (void)
{
  /*
   * MLDSA-44, MLDSA-65, and MLDSA-87 tests include the following test cases:
   * 1. message "hello" and context string "tests"
   * 2. tampered message "hello test" and context string "tests"
   * 3. message "hello" and tampered context string "tampered"
   * 4. message "hello", context string "tests" and tampered pubkey
   */
  mldsa_sexp_test (GCRY_MLDSA44, pub44_key, pub44_key_len, sig44_with_ctx,
                   sig44_with_ctx_len, 1);
  mldsa_sexp_test (GCRY_MLDSA65, pub65_key, pub65_key_len, sig65_with_ctx,
                   sig65_with_ctx_len, 1);
  mldsa_sexp_test (GCRY_MLDSA87, pub87_key, pub87_key_len, sig87_with_ctx,
                   sig87_with_ctx_len, 1);

  /*
   * MLDSA-44, MLDSA-65, and MLDSA-87 tests include the following test cases:
   * 1. message "hello" and empty context string ""
   * 2. tampered message "hello test" and empty context string ""
   * 3. message "hello", empty context string "" and tampered pubkey
   */
  mldsa_sexp_test (GCRY_MLDSA44, pub44_key, pub44_key_len, sig44_without_ctx,
                   sig44_without_ctx_len, 0);
  mldsa_sexp_test (GCRY_MLDSA65, pub65_key, pub65_key_len, sig65_without_ctx,
                   sig65_without_ctx_len, 0);
  mldsa_sexp_test (GCRY_MLDSA87, pub87_key, pub87_key_len, sig87_without_ctx,
                   sig87_without_ctx_len, 0);

  /*
   * MLDSA-44, MLDSA-65, and MLDSA-87 tests include the following test cases:
   * 1. greater than 65535 bytes of message and context string "tests"
   * 2. tampered message "hello test" and context string "tests"
   * 3. greater than 65535 bytes of message and tampered context string "tampered"
   * 4. greater than 65535 bytes of message, context string "tests" and tampered pubkey
   */
  mldsa_raw_test (GCRY_MLDSA44, pub44_key, pub44_key_len, sig44_lmsg_with_ctx,
                  sig44_lmsg_with_ctx_len, 1);
  mldsa_raw_test (GCRY_MLDSA65, pub65_key, pub65_key_len, sig65_lmsg_with_ctx,
                  sig65_lmsg_with_ctx_len, 1);
  mldsa_raw_test (GCRY_MLDSA87, pub87_key, pub87_key_len, sig87_lmsg_with_ctx,
                  sig87_lmsg_with_ctx_len, 1);

  /*
   * MLDSA-44, MLDSA-65, and MLDSA-87 tests include the following test cases:
   * 1. greater than 65535 bytes of message and empty context string ""
   * 2. tampered message "hello test" and empty context string ""
   * 3. greater than 65535 bytes of message, empty context string "" and tampered pubkey
   */
  mldsa_raw_test (GCRY_MLDSA44, pub44_key, pub44_key_len, sig44_lmsg_without_ctx,
                  sig44_lmsg_without_ctx_len, 0);
  mldsa_raw_test (GCRY_MLDSA65, pub65_key, pub65_key_len, sig65_lmsg_without_ctx,
                  sig65_lmsg_without_ctx_len, 0);
  mldsa_raw_test (GCRY_MLDSA87, pub87_key, pub87_key_len, sig87_lmsg_without_ctx,
                  sig87_lmsg_without_ctx_len, 0);
}

GRUB_FUNCTIONAL_TEST (mldsa_test, mldsa_test);
