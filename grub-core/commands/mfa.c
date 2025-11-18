/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025 Free Software Foundation, Inc.
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

#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/key_protector.h>
#include <grub/cryptodisk.h>

GRUB_MOD_LICENSE ("GPLv3+");

typedef enum mfa_options
{
  OPTION_PROTECTOR1,
  OPTION_PROTECTOR2,
} mfa_options_t;

typedef struct mfa_context
{
  const char *protector1;
  const char *protector2;
} mfa_context_t;

static const struct grub_arg_option mfa_init_cmd_options[] =
  {
    {
      .longarg  = "protector1",
      .shortarg = '1',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_("The first key protector"),
    },
    {
      .longarg  = "protector2",
      .shortarg = '2',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_("The second key protector"),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

typedef enum password_options
{
  OPTION_PASSWORD
} password_options_t;

typedef struct password_context
{
  grub_uint8_t *password;
  grub_size_t password_len;
} password_context_t;

static const struct grub_arg_option password_init_cmd_options[] =
  {
    {
      .longarg  = "password",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_("Password"),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

typedef enum file_options
{
  OPTION_KEYFILE,
  OPTION_KEYFILE_OFFSET,
  OPTION_KEYFILE_SIZE,
} file_options_t;

typedef struct file_context
{
  const char *keyfile;
  unsigned long long keyfile_offset;
  unsigned long long keyfile_size;
} file_context_t;

static const struct grub_arg_option file_init_cmd_options[] =
  {
    {
      .longarg  = "key-file",
      .shortarg = 'k',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_("Key file"),
    },
    {
      .longarg  = "keyfile-offset",
      .shortarg = 'O',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_INT,
      .doc      = N_("Key file offset (bytes)"),
    },
    {
      .longarg  = "keyfile-size",
      .shortarg = 'S',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_INT,
      .doc      = N_("Key file data size (bytes)"),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static grub_extcmd_t mfa_init_cmd;
static grub_extcmd_t mfa_clear_cmd;
static mfa_context_t mfa_ctx = {0};

static grub_extcmd_t password_init_cmd;
static grub_extcmd_t password_clear_cmd;
static password_context_t password_ctx = {0};

static grub_extcmd_t file_init_cmd;
static grub_extcmd_t file_clear_cmd;
static file_context_t file_ctx = {0};

static grub_err_t
mfa_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  grub_uint8_t *p1_key = NULL, *p2_key = NULL;
  grub_size_t p1_size, p2_size, total_size;
  grub_err_t err;

  if (mfa_ctx.protector1 == NULL || mfa_ctx.protector2 == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("MFA key protector(s) not set"));

  grub_printf_ (N_("Retrieving MFA key 1 from '%s' key protector\n"), mfa_ctx.protector1);
  err = grub_key_protector_recover_key (mfa_ctx.protector1, &p1_key, &p1_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  grub_printf_ (N_("Retrieving MFA key 2 from '%s' key protector\n"), mfa_ctx.protector2);
  err = grub_key_protector_recover_key (mfa_ctx.protector2, &p2_key, &p2_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  total_size = p1_size + p2_size;
  if (total_size < p1_size || total_size < p2_size || total_size == 0)
    {
      err = grub_error (GRUB_ERR_BAD_NUMBER, N_("invalid MFA key size"));
      goto error;
    }

  *key_size = total_size;
  *key = grub_malloc (*key_size);
  if (*key == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }

  grub_memcpy (*key, p1_key, p1_size);
  grub_memcpy (*key + p1_size, p2_key, p2_size);

  err = GRUB_ERR_NONE;

error:
  /* Erase the intermediate keys */
  if (p1_key != NULL)
    {
      grub_memset (p1_key, 0, p1_size);
      grub_free (p1_key);
    }
  if (p2_key != NULL)
    {
      grub_memset (p2_key, 0, p2_size);
      grub_free (p2_key);
    }

  return err;
}

static grub_err_t
password_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  char password[GRUB_CRYPTODISK_MAX_PASSPHRASE];
  grub_err_t err;

  if (password_ctx.password_len != 0)
    {
      *key = password_ctx.password;
      *key_size = password_ctx.password_len;

      /* Reset 'password' to avoid the potential double-free in password_clear_cmd_handler() */
      password_ctx.password = NULL;
      password_ctx.password_len = 0;

      return GRUB_ERR_NONE;
    }

  grub_printf_ (N_("Enter MFA passphrase: "));
  if (grub_password_get (password , GRUB_CRYPTODISK_MAX_PASSPHRASE) == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("passphrase not supplied"));

  *key_size = grub_strlen (password);
  *key = grub_malloc (*key_size);
  if (*key == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }

  grub_memcpy (*key, password, *key_size);

  err = GRUB_ERR_NONE;

error:
  grub_memset (password, 0, GRUB_CRYPTODISK_MAX_PASSPHRASE);

  return err;
}

static grub_err_t
file_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  const char *filepath;
  grub_file_t file;
  grub_off_t file_size;
  void *read_buffer;
  grub_off_t read_n;
  grub_err_t err;

  if (file_ctx.keyfile == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("file path not supplied"));

  filepath = file_ctx.keyfile;

  file = grub_file_open (filepath, GRUB_FILE_TYPE_CRYPTODISK_ENCRYPTION_KEY);
  if (file == NULL)
    {
      /* Push errno from grub_file_open() into the error message stack */
      grub_error_push ();
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("could not open file: %s"), filepath);
      goto error;
    }

  file_size = grub_file_size (file);
  if (file_size == 0)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE, N_("empty file: %s"), filepath);
      goto error;
    }
  else if (file_size == GRUB_FILE_SIZE_UNKNOWN)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE, N_("could not read file size: %s"), filepath);
      goto error;
    }

  if (file_ctx.keyfile_offset > file_size)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE,
			N_("Keyfile offset, %llu, is greater than keyfile size, %llu"),
			   file_ctx.keyfile_offset, (unsigned long long) file_size);
      goto error;
    }


  if (file_ctx.keyfile_size != 0)
    {
      if (file_ctx.keyfile_size > (file_size - file_ctx.keyfile_offset))
	{
	  err = grub_error (GRUB_ERR_FILE_READ_ERROR,
			    N_("keyfile is too small: requested %llu bytes,"
			       " but the file only has %llu bytes left at offset %llu"),
			    file_ctx.keyfile_size,
			    (unsigned long long) (file_size - file_ctx.keyfile_offset),
			    file_ctx.keyfile_offset);
	  goto error;
	}
      *key_size = file_ctx.keyfile_size;
    }
  else
    *key_size = file_size;

  if (grub_file_seek (file, (grub_off_t) file_ctx.keyfile_offset) == (grub_off_t) -1)
    {
      err = grub_errno;
      goto error;
    }

  read_buffer = grub_malloc (*key_size);
  if (read_buffer == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("could not allocate buffer for %s"), filepath);
      goto error;
    }

  read_n = grub_file_read (file, read_buffer, *key_size);
  if (read_n != *key_size)
    {
      grub_free (read_buffer);
      err = grub_error (GRUB_ERR_FILE_READ_ERROR, N_("could not retrieve file contents: %s"), filepath);
      goto error;
    }

  *key = read_buffer;

  err = GRUB_ERR_NONE;

 error:
  if (file != NULL)
    grub_file_close (file);

  return err;
}

static grub_err_t
mfa_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
		      char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  grub_err_t err;

  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("the MFA key protector does not accept any non-option arguments "
			  "(i.e., like -o and/or --option only)"));

  grub_free ((void *) mfa_ctx.protector1);
  grub_free ((void *) mfa_ctx.protector2);
  grub_memset (&mfa_ctx, 0, sizeof (mfa_ctx));

  if (state[OPTION_PROTECTOR1].set)  /* protector1 */
    mfa_ctx.protector1 = grub_strdup (state[OPTION_PROTECTOR1].arg);

  if (state[OPTION_PROTECTOR2].set)  /* protector2 */
    mfa_ctx.protector2 = grub_strdup (state[OPTION_PROTECTOR2].arg);

  if (mfa_ctx.protector1 == NULL || mfa_ctx.protector2 == NULL)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
			N_("the MFA key protector needs two key protectors"));
      goto error;
    }

  if (grub_strcmp (mfa_ctx.protector1, mfa_ctx.protector2) == 0)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
			N_("the MFA key protector needs two different key protectors"));
      goto error;
    }

  if (grub_strcmp (mfa_ctx.protector1, "mfa") == 0 || grub_strcmp (mfa_ctx.protector2, "mfa") == 0)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
			N_("calling the MFA key protector recursively is not allowed"));
      goto error;
    }

  /* This command only initializes the protector, so nothing else to do. */

  return GRUB_ERR_NONE;

 error:
  grub_free ((void *) mfa_ctx.protector1);
  grub_free ((void *) mfa_ctx.protector2);
  grub_memset (&mfa_ctx, 0, sizeof (mfa_ctx));

  return err;
}

static grub_err_t
mfa_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		       int argc, char **args __attribute__ ((unused)))
{
  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("mfa_key_protector_clear accepts no arguments"));

  grub_free ((void *) mfa_ctx.protector1);
  grub_free ((void *) mfa_ctx.protector2);
  grub_memset (&mfa_ctx, 0, sizeof (mfa_ctx));

  return GRUB_ERR_NONE;
}

static grub_err_t
password_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
			   char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;

  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("the password key protector does not accept any non-option arguments (i.e., like -o and/or --option only)"));

  grub_free ((void *) password_ctx.password);
  grub_memset (&password_ctx, 0, sizeof (password_ctx));

  if (state[OPTION_PASSWORD].set)  /* password */
    {
      password_ctx.password = (grub_uint8_t *) grub_strdup (state[OPTION_PASSWORD].arg);
      password_ctx.password_len = grub_strlen (state[OPTION_PASSWORD].arg);
    }

  /* This command only initializes the protector, so nothing else to do. */

  return GRUB_ERR_NONE;
}

static grub_err_t
password_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
			    int argc, char **args __attribute__ ((unused)))
{
  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("pw_key_protector_clear accepts no arguments"));

  grub_free ((void *) password_ctx.password);
  grub_memset (&password_ctx, 0, sizeof (password_ctx));

  return GRUB_ERR_NONE;
}

static grub_err_t
file_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
		       char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  unsigned long long keyfile_offset = 0, keyfile_size = 0;
  const char *p = NULL;

  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("the file key protector does not accept any non-option arguments (i.e., like -o and/or --option only)"));

  grub_free ((void *) file_ctx.keyfile);
  grub_memset (&file_ctx, 0, sizeof (file_ctx));

  if (state[OPTION_KEYFILE_OFFSET].set) /* keyfile-offset */
    {
      grub_errno = GRUB_ERR_NONE;
      keyfile_offset = grub_strtoull (state[OPTION_KEYFILE_OFFSET].arg, &p, 0);

      if (state[OPTION_KEYFILE_OFFSET].arg[0] == '\0' || *p != '\0')
	return grub_error (grub_errno,
			   N_("non-numeric or invalid keyfile offset `%s'"),
			   state[OPTION_KEYFILE_OFFSET].arg);
    }

  if (state[OPTION_KEYFILE_SIZE].set) /* keyfile-size */
    {
	  grub_errno = GRUB_ERR_NONE;
	  keyfile_size = grub_strtoull (state[OPTION_KEYFILE_SIZE].arg, &p, 0);

	  if (state[OPTION_KEYFILE_SIZE].arg[0] == '\0' || *p != '\0')
	    return grub_error (grub_errno,
			       N_("non-numeric or invalid keyfile size `%s'"),
			       state[OPTION_KEYFILE_SIZE].arg);

	  if (keyfile_size == 0)
	    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("key file size is 0"));

	  if (keyfile_size > GRUB_CRYPTODISK_MAX_KEYFILE_SIZE)
	    return grub_error (GRUB_ERR_OUT_OF_RANGE,
			       N_("key file size exceeds maximum (%d)"),
			       GRUB_CRYPTODISK_MAX_KEYFILE_SIZE);
    }

  if (state[OPTION_KEYFILE].set)  /* key-file */
    file_ctx.keyfile = grub_strdup (state[OPTION_KEYFILE].arg);

  if (file_ctx.keyfile == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("no file specified for the file key protector"));

  file_ctx.keyfile_offset = keyfile_offset;
  file_ctx.keyfile_size = keyfile_size;

  /* This command only initializes the protector, so nothing else to do. */

  return GRUB_ERR_NONE;
}

static grub_err_t
file_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
			int argc, char **args __attribute__ ((unused)))
{
  if (argc > 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("file_key_protector_clear accepts no arguments"));

  grub_free ((void *) file_ctx.keyfile);
  grub_memset (&file_ctx, 0, sizeof (file_ctx));

  return GRUB_ERR_NONE;
}

static struct grub_key_protector mfa_key_protector =
  {
    .name = "mfa",
    .recover_key = mfa_recover_key
  };

static struct grub_key_protector password_key_protector =
  {
    .name = "password",
    .recover_key = password_recover_key
  };

static struct grub_key_protector file_key_protector =
  {
    .name = "file",
    .recover_key = file_recover_key
  };

GRUB_MOD_INIT (mfa)
{
  mfa_init_cmd =
    grub_register_extcmd ("mfa_key_protector_init",
			  mfa_init_cmd_handler, 0,
			  N_("[-1 protector] [-2 protector]"),
			  N_("Initialize the MFA key protector."),
			  mfa_init_cmd_options);
  mfa_clear_cmd =
    grub_register_extcmd ("mfa_key_protector_clear",
			  mfa_clear_cmd_handler, 0, NULL,
			  N_("Clear the MFA key protector if previously initialized."),
			  NULL);

  password_init_cmd =
    grub_register_extcmd ("pw_key_protector_init",
			  password_init_cmd_handler, 0,
			  N_("[-p password]"),
			  N_("Initialize the password key protector."),
			  password_init_cmd_options);
  password_clear_cmd =
    grub_register_extcmd ("pw_key_protector_clear",
			  password_clear_cmd_handler, 0, NULL,
			  N_("Clear the password key protector if previously initialized."),
			  NULL);

  file_init_cmd =
    grub_register_extcmd ("file_key_protector_init",
			  file_init_cmd_handler, 0,
			  N_("[-k path] [-O offset] [-S size]"),
			  N_("Initialize the file key protector."),
			  file_init_cmd_options);
  file_clear_cmd =
    grub_register_extcmd ("file_key_protector_clear",
			  file_clear_cmd_handler, 0, NULL,
			  N_("Clear the file key protector if previously initialized."),
			  NULL);

  grub_key_protector_register (&mfa_key_protector);
  grub_key_protector_register (&password_key_protector);
  grub_key_protector_register (&file_key_protector);
}

GRUB_MOD_FINI (mfa)
{
  grub_key_protector_unregister (&file_key_protector);
  grub_key_protector_unregister (&password_key_protector);
  grub_key_protector_unregister (&mfa_key_protector);

  grub_unregister_extcmd (file_clear_cmd);
  grub_unregister_extcmd (file_init_cmd);

  grub_unregister_extcmd (password_clear_cmd);
  grub_unregister_extcmd (password_init_cmd);

  grub_unregister_extcmd (mfa_clear_cmd);
  grub_unregister_extcmd (mfa_init_cmd);
}
