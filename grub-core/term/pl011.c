/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026  Free Software Foundation, Inc.
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

#include <grub/serial.h>
#include <grub/pl011.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/time.h>
#include <grub/i18n.h>

static grub_uint32_t
pl011_read (struct grub_serial_port *port, grub_addr_t reg)
{
  asm volatile("" : : : "memory");
  switch(port->mmio.access_size)
    {
    case 2:
      return *((volatile grub_uint16_t *) (port->mmio.base + reg));
    case 4:
    default:
      return *((volatile grub_uint32_t *) (port->mmio.base + reg));
    }
}

static void
pl011_write (struct grub_serial_port *port, grub_uint32_t value, grub_addr_t reg)
{
  asm volatile("" : : : "memory");
  switch(port->mmio.access_size)
    {
    case 2:
      *((volatile grub_uint16_t *) (port->mmio.base + reg)) = value;
      break;
    case 4:
    default:
      *((volatile grub_uint32_t *) (port->mmio.base + reg)) = value;
      break;
    }
}

/* Convert speed to divisor.  */
static grub_int32_t
pl011_get_divisor (const struct grub_serial_port *port __attribute__ ((unused)),
            const struct grub_serial_config *config)
{
  if (config->speed == 0)
    return -1;

  return grub_divmod64 ((config->base_clock << 2) + (config->speed >> 1),
             config->speed, NULL);
}

static void
do_real_config (struct grub_serial_port *port)
{
  grub_uint32_t cr;
  grub_uint32_t lcrh = 0;
  grub_int32_t divisor;
  grub_uint64_t endtime;

  const grub_uint32_t word_lens[] = {
    [5] = UART011_LCRH_WLEN_5,
    [6] = UART011_LCRH_WLEN_6,
    [7] = UART011_LCRH_WLEN_7,
    [8] = UART011_LCRH_WLEN_8,
  };
  const grub_uint32_t parities[] = {
    [GRUB_SERIAL_PARITY_NONE] = 0,
    [GRUB_SERIAL_PARITY_ODD]  = UART011_LCRH_PEN,
    [GRUB_SERIAL_PARITY_EVEN] = UART011_LCRH_PEN | UART011_LCRH_EPS,
  };
  const grub_uint32_t stop_bits[] = {
    [GRUB_SERIAL_STOP_BITS_1] = 0,
    [GRUB_SERIAL_STOP_BITS_2] = UART011_LCRH_STP2,
  };

  if (port->configured)
    return;

  /* Disable the serial port.  */
  cr = pl011_read (port, UART011_CR);
  cr &= UART011_CR_RTS | UART011_CR_DTR;
  pl011_write (port, cr, UART011_CR);

  /* Turn off the interrupt.  */
  pl011_write (port, 0, UART011_IMSC);
  pl011_write (port, 0xffff, UART011_ICR);

  /* Set the divisor.  */
  divisor = pl011_get_divisor (port, &port->config);
  if (divisor > 0)
    {
      pl011_write (port, divisor >> 6, UART011_IBRD);
      pl011_write (port, divisor & 63, UART011_FBRD);
    }

  /* Set the line control.  */
  lcrh |= word_lens[port->config.word_len]
       | parities[port->config.parity]
       | stop_bits[port->config.stop_bits]
       | UART011_LCRH_FEN;
  pl011_write (port, lcrh, UART011_LCRH);

  /* Set the RTSCTS.  */
  if (port->config.rtscts)
    {
      if (cr & UART011_CR_RTS)
        cr |= UART011_CR_RTSEN;
      cr |= UART011_CR_CTSEN;
    }
  else
    {
      cr &= ~(UART011_CR_CTSEN | UART011_CR_RTSEN);
    }

  /* Enable the serial port.  */
  cr |= UART011_CR_UARTEN | UART011_CR_RXE | UART011_CR_TXE;
  pl011_write (port, cr, UART011_CR);

  /* Drain the input buffer.  */
  endtime = grub_get_time_ms () + 1000;
  while (grub_get_time_ms () <= endtime)
    {
      if (pl011_read (port, UART011_FR) & UART011_FR_RXFE)
        break;
      pl011_read (port, UART011_DR);
    }

  port->configured = 1;
}

/* Fetch a key.  */
static int
serial_hw_fetch (struct grub_serial_port *port)
{
  do_real_config (port);

  if (pl011_read (port, UART011_FR) & UART011_FR_RXFE)
    return -1;

  return pl011_read (port, UART011_DR);
}

/* Put a character.  */
static void
serial_hw_put (struct grub_serial_port *port, const int c)
{
  do_real_config (port);

  while ((pl011_read (port, UART011_FR) & UART011_FR_TXFF))
    asm volatile("" : : : "memory");

  pl011_write (port, c, UART011_DR);
}

/* Initialize a serial device. */
static grub_err_t
serial_hw_configure (struct grub_serial_port *port,
             struct grub_serial_config *config)
{
  grub_int32_t divisor;

  divisor = pl011_get_divisor (port, config);
  if (divisor < 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
               N_("unsupported serial port speed"));
  else if (divisor == 0 && port->configured)
    grub_printf ("Note: missing base clock, keeping current serial speed\n");

  if (config->parity != GRUB_SERIAL_PARITY_NONE
      && config->parity != GRUB_SERIAL_PARITY_ODD
      && config->parity != GRUB_SERIAL_PARITY_EVEN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
               N_("unsupported serial port parity"));

  if (config->stop_bits != GRUB_SERIAL_STOP_BITS_1
      && config->stop_bits != GRUB_SERIAL_STOP_BITS_2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
               N_("unsupported serial port stop bits number"));

  if (config->word_len < 5 || config->word_len > 8)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
               N_("unsupported serial port word length"));

  port->config = *config;
  port->configured = 0;

  return GRUB_ERR_NONE;
}

struct grub_serial_driver grub_pl011_driver =
  {
    .configure = serial_hw_configure,
    .fetch = serial_hw_fetch,
    .put = serial_hw_put
  };

struct grub_serial_port *
grub_serial_pl011_add_mmio (grub_addr_t addr, unsigned int acc_size,
                            struct grub_serial_config *config, bool trusted)
{
  struct grub_serial_port *p;

  /*
   * use_mmio and mmio share a union with the private data of every other back
   * end, so they only mean anything on a port this driver registered.
   */
  FOR_SERIAL_PORTS (p)
    if (p->driver == &grub_pl011_driver
        && p->use_mmio == true && p->mmio.base == addr)
      {
        if (config != NULL)
          grub_serial_port_configure (p, config);
        return p;
      }

  /* No port is registered here, so going on means programming the address. */
  if (grub_serial_reject_untrusted_address (trusted) == true)
    return NULL;

  p = grub_malloc (sizeof (*p));
  if (p == NULL)
    return NULL;
  p->name = grub_xasprintf ("mmio,%llx", (unsigned long long) addr);
  if (p->name == NULL)
    {
      grub_free (p);
      return NULL;
    }
  p->driver = &grub_pl011_driver;
  p->use_mmio = true;
  p->mmio.base = addr;
  p->mmio.access_size = acc_size;
  if (config != NULL)
    grub_serial_port_configure (p, config);
  else
    grub_serial_config_defaults (p);
  grub_serial_register (p);

  return p;
}
