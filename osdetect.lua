#!lua
--
-- Copyright (C) 2009  Free Software Foundation, Inc.
--
-- GRUB is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- GRUB is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
--

function enum_device (device, fs, uuid)
  local root
  local title
  local source
  local kernels = {}
  local kernelnames = {}
  local kernel_num = 0

  local function enum_file (name)
    local version

    version = string.match (name, "vmlinuz%-(.*)")
    if (version == nil) then
      version = string.match (name, "linux%-(.*)")
    end
    if (version ~= nil) then
      table.insert (kernels, version)
      table.insert (kernelnames, name)
      kernel_num = kernel_num + 1
    end
  end

  local function sort_kernel (first, second)
    local a1, a2, a3, a4, b1, b2, b3, b4

    a1, a2, a3, a4 = string.match (first, "(%d+)%.?(%d*).?(%d*)%-?(%d*)")
    b1, b2, b3, b4 = string.match (second, "(%d+)%.?(%d*).?(%d*)%-?(%d*)")
    return (a1 > b1) or (a2 > b2) or (a3 > b3) or (a4 < b4);
  end
  local function freebsd_variants (title, header, footer)
    normal = "\nset FreeBSD.acpi_load=YES" ..
    "\nset FreeBSD.hint.acpi.0.disabled=0"
    noacpi = "\nunset FreeBSD.acpi_load" ..
    "\nset FreeBSD.hint.acpi.0.disabled=1" ..
    "\nset FreeBSD.loader.acpi_disabled_by_user=1"
    safe = "\nset FreeBSD.hint.apic.0.disabled=1" ..
	"\nset FreeBSD.hw.ata.ata_dma=0" ..
        "\nset FreeBSD.hw.ata.atapi_dma=0" ..
        "\nset FreeBSD.hw.ata.wc=0" ..
        "\nset FreeBSD.hw.eisa_slots=0" ..
        "\nset FreeBSD.hint.kbdmux.0.disabled=1"
    grub.add_menu (header .. normal .. footer, title)
    grub.add_menu (header .. " --single" .. normal .. footer,
		   title .. " (single)")
    grub.add_menu (header .. " --verbose" .. normal .. footer,
		   title .. " (verbose)")
    grub.add_menu (header .. " --verbose" .. noacpi .. footer,
		   title .. " (without ACPI)")
    grub.add_menu (header .. " --verbose" .. noacpi .. safe .. footer,
		   title .. " (safe mode)")
  end

  root = "(" .. device .. ")/"
  source = "root (" .. device .. ")\nchainloader +1"
  title = nil
  if (grub.file_exist (root .. "bootmgr") and
      grub.file_exist (root .. "boot/bcd")) then
    title = "Windows Vista bootmgr"
  elseif (grub.file_exist (root .. "ntldr") and
	  grub.file_exist (root .. "ntdetect.com") and
	  grub.file_exist (root .. "boot.ini")) then
    title = "Windows NT/2000/XP loader"
  elseif (grub.file_exist (root .. "windows/win.com")) then
    title = "Windows 98/ME"
  elseif (grub.file_exist (root .. "io.sys") and
	  grub.file_exist (root .. "command.com")) then
    title = "MS-DOS"
  elseif (grub.file_exist (root .. "kernel.sys")) then
    title = "FreeDOS"
  elseif ((fs == "ufs1" or fs == "ufs2") and grub.file_exist (root .. "boot/kernel/kernel") and
	  grub.file_exist (root .. "boot/device.hints")) then
     header = "set root=" .. device .. "\nfreebsd /boot/kernel/kernel"
     footer = "\nset FreeBSD.vfs.root.mountfrom=ufs:ufsid/" .. uuid ..
	"\nfreebsd_loadenv /boot/device.hints"
     title = "FreeBSD (on " .. fs .. " ".. device .. ")"
     freebsd_variants (title, header, footer)
     return 0
  elseif (fs == "zfs" and grub.file_exist (root .. "/@/boot/kernel/kernel") and
      grub.file_exist (root .. "/@/boot/device.hints")) then
     header = "set root=" .. device .. "\nfreebsd /@/boot/kernel/kernel"
     footer =  "\nfreebsd_module_elf /@/boot/kernel/opensolaris.ko" ..
      "\nfreebsd_module_elf /@/boot/kernel/zfs.ko" ..
      "\nfreebsd_module /@/boot/zfs/zpool.cache type=/boot/zfs/zpool.cache" ..
      "\nprobe -l -s name $root" ..
      "\nset FreeBSD.vfs.root.mountfrom=zfs:$name" ..
      "\nfreebsd_loadenv /@/boot/device.hints"
     title = "FreeBSD (on " .. fs .. " ".. device .. ")"
     freebsd_variants (title, header, footer)
     return 0
  else
    grub.enum_file (enum_file, root .. "boot")
    if kernel_num ~= 0 then
      table.sort (kernels, sort_kernel)
      for i = 1, kernel_num do
	local initrd

	title = "Linux " .. kernels[i]
	source = "set root = " .. device ..
	  "\nlinux /boot/" .. kernelnames[i] ..
	  " root=UUID=" ..  " ro"

	if grub.file_exist (root .. "boot/initrd-" ..
			    kernels[i] .. ".img") then
	  initrd = "\ninitrd /boot/initrd-" .. kernels[i] .. ".img"
	elseif grub.file_exist (root .. "boot/initrd.img-" .. kernels[i]) then
	  initrd = "\ninitrd /boot/initrd.img-" .. kernels[i]
	elseif grub.file_exist (root .. "boot/initrd-" .. kernels[i]) then
	  initrd = "\ninitrd /boot/initrd-" .. kernels[i]
	else
	  initrd = ""
	end

	grub.add_menu (source .. initrd, title)
	grub.add_menu (source .. " single" .. initrd,
		       title .. " (single-user mode)")
      end
      return 0
    end
  end

  if title == nil then
    local partition = string.match (device, ".*,(%d+)")

    if (partition ~= nil) and (tonumber (partition) > 4) then
      return 0
    end

    title = "Other OS"
  end

  grub.add_menu (source, title)
  return 0
end

grub.enum_device (enum_device)
