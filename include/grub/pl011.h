/* pl011.h - serial device interface */
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

#ifndef GRUB_PL011_HEADER
#define GRUB_PL011_HEADER 1

/* Macros.  */

/* The offsets of UART registers.  */
#define UART011_DR    0x00 /* Data read or written from the interface. */
#define UART011_FR    0x18 /* Flag register (Read only). */
#define UART011_IBRD  0x24 /* Integer baud rate divisor register. */
#define UART011_FBRD  0x28 /* Fractional baud rate divisor register. */
#define UART011_LCRH  0x2c /* Line control register. */
#define UART011_CR    0x30 /* Control register. */
#define UART011_IFLS  0x34 /* Interrupt fifo level select. */
#define UART011_IMSC  0x38 /* Interrupt mask. */
#define UART011_RIS   0x3c /* Raw interrupt status. */
#define UART011_MIS   0x40 /* Masked interrupt status. */
#define UART011_ICR   0x44 /* Interrupt clear register. */
#define UART011_DMACR 0x48 /* DMA control register. */

#define UART011_FR_RXFE (1 << 4)
#define UART011_FR_TXFF (1 << 5)

#define UART011_CR_UARTEN (1 << 0)  /* UART enable */
#define UART011_CR_TXE    (1 << 8)  /* transmit enable */
#define UART011_CR_RXE    (1 << 9)  /* receive enable */
#define UART011_CR_DTR    (1 << 10) /* DTR */
#define UART011_CR_RTS    (1 << 11) /* RTS */
#define UART011_CR_RTSEN  (1 << 14) /* RTS hardware flow control */
#define UART011_CR_CTSEN  (1 << 15) /* CTS hardware flow control */

#define UART011_LCRH_WLEN_5 0x00
#define UART011_LCRH_WLEN_6 0x20
#define UART011_LCRH_WLEN_7 0x40
#define UART011_LCRH_WLEN_8 0x60
#define UART011_LCRH_PEN    (1 << 1)
#define UART011_LCRH_EPS    (1 << 2)
#define UART011_LCRH_STP2   (1 << 3)
#define UART011_LCRH_FEN    (1 << 4)

#ifndef ASM_FILE
struct grub_serial_port *grub_serial_pl011_add_mmio (grub_addr_t addr,
                              unsigned int acc_size,
                              struct grub_serial_config *config,
                              bool trusted);
#endif

#endif /* ! GRUB_PL011_HEADER */
