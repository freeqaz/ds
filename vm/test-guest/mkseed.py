# SPDX-License-Identifier: Apache-2.0
#
# mkseed.py — minimal, deterministic ISO9660 writer for the NoCloud cloud-init
# seed used by the local test-guest rig (vm/test-guest/).
#
# WHY this exists. The recommended test-guest seed is a NoCloud ISO carrying
# `meta-data` / `user-data` / `network-config`; cloud-init's NoCloud datasource
# picks it up by the ISO9660 volume label `cidata` (case-insensitive). The
# canonical builders (genisoimage / xorriso / cloud-localds) are not present in
# every environment this rig must run in (the sudo-free qemu sandbox has none),
# so build-test-guest.sh prefers a real tool when one is on PATH and falls back
# to THIS pure-stdlib writer. There are NO third-party imports — only the Python
# standard library — so it runs anywhere a Python 3 interpreter exists.
#
# SCOPE. This writes a single-directory, ISO9660 (ECMA-119) Level-1-ish image:
# a Primary Volume Descriptor + Volume Descriptor Set Terminator, one root
# directory record, and the handful of small seed files. It intentionally does
# NOT implement Joliet/Rock-Ridge, multi-level directories, or files spanning
# behaviour beyond what a NoCloud seed needs (the files are a few hundred bytes
# each). cloud-init only needs the volume label + the three filenames readable,
# which a plain ISO9660 PVD provides. The output is byte-deterministic given the
# same inputs (fixed/zero timestamps), so the same seed inputs reproduce the
# same ISO — important for a reproducible builder.
#
# NOT a general-purpose ISO tool. If you need anything beyond the NoCloud seed,
# install genisoimage/xorriso; build-test-guest.sh will use it automatically.
#
# Usage:
#   python3 mkseed.py <out.iso> <name1>=<path1> [<name2>=<path2> ...]
#     - <nameN> is the 8.3-style filename as it must appear in the image
#       (e.g. META_DAT, USER_DAT). cloud-init reads by content, but the NoCloud
#       datasource expects the on-disk names meta-data/user-data/network-config;
#       build-test-guest.sh maps those onto the ISO via the standard
#       "FILENAME.;1" ISO9660 identifier (see iso_name()).
#
# The actual filename mapping the seed needs (meta-data, user-data,
# network-config) is handled by passing the real names; iso_name() upper-cases
# and version-suffixes them per ISO9660 so cloud-init's case-insensitive match
# still resolves them.

import struct
import sys

SECTOR = 2048


def iso_name(name):
    # ISO9660 identifiers are UPPERCASE; the version suffix ";1" is mandatory.
    # cloud-init lowercases when matching, so META-DATA.;1 resolves to
    # "meta-data". '-' is not a strict d-char but is widely accepted by
    # ISO9660 readers (and by the Linux isofs driver cloud-init uses); we keep
    # it so the on-disk names match what NoCloud documents.
    return (name.upper() + ".;1").encode("ascii")


def both_endian_16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def both_endian_32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def pad_sector(buf):
    rem = len(buf) % SECTOR
    if rem:
        buf += b"\x00" * (SECTOR - rem)
    return buf


def dec_datetime():
    # "no date" form per ECMA-119 8.4.26.1: all-'0' digits + GMT offset 0.
    return b"0000000000000000" + bytes([0])


def dir_datetime():
    # 7-byte directory-record timestamp, all zero (years-since-1900 = 0 etc.).
    return bytes(7)


def dir_record(name_bytes, extent_lba, length, flags):
    # ECMA-119 9.1 directory record. len_dr must be even.
    base = 33 + len(name_bytes)
    if base % 2:
        pad = 1
    else:
        pad = 0
    len_dr = base + pad
    rec = bytearray()
    rec.append(len_dr)
    rec.append(0)  # extended attr record length
    rec += both_endian_32(extent_lba)
    rec += both_endian_32(length)
    rec += dir_datetime()
    rec.append(flags)
    rec.append(0)  # file unit size (non-interleaved)
    rec.append(0)  # interleave gap
    rec += both_endian_16(1)  # volume sequence number
    rec.append(len(name_bytes))
    rec += name_bytes
    if pad:
        rec.append(0)
    return bytes(rec)


def build(out_path, files):
    # files: list of (iso_name_bytes, data_bytes), already ordered.
    # Layout (LBA, one logical block == one 2048-byte sector):
    #   16  Primary Volume Descriptor
    #   17  Volume Descriptor Set Terminator
    #   18  root directory
    #   19+ file contents (one+ sectors each)
    pvd_lba = 16
    root_lba = 18
    file_lba = root_lba + 1

    # Assign extents to files.
    placed = []
    lba = file_lba
    for nm, data in files:
        sectors = (len(data) + SECTOR - 1) // SECTOR or 1
        placed.append((nm, data, lba, len(data)))
        lba += sectors
    total_sectors = lba  # number of logical blocks in the volume

    # --- Root directory contents ---
    root_dir = bytearray()
    # '.' entry (name = 0x00), '..' entry (name = 0x01), both pointing at root.
    root_dir += dir_record(b"\x00", root_lba, SECTOR, 0x02)
    root_dir += dir_record(b"\x01", root_lba, SECTOR, 0x02)
    for nm, data, flba, length in placed:
        root_dir += dir_record(nm, flba, length, 0x00)
    root_dir_len = len(root_dir)
    root_dir = pad_sector(bytes(root_dir))

    # The root directory record embedded in the PVD (34 bytes, name = 0x00).
    root_rec = dir_record(b"\x00", root_lba, root_dir_len, 0x02)
    assert len(root_rec) == 34, len(root_rec)

    # --- Primary Volume Descriptor (ECMA-119 8.4) ---
    def strA(s, n):
        return s.encode("ascii").ljust(n)[:n]

    pvd = bytearray()
    pvd.append(1)            # volume descriptor type = primary
    pvd += b"CD001"          # standard identifier
    pvd.append(1)            # version
    pvd.append(0)            # unused
    pvd += strA("", 32)      # system identifier
    pvd += strA("cidata", 32)  # volume identifier  <-- the NoCloud label
    pvd += bytes(8)          # unused
    pvd += both_endian_32(total_sectors)  # volume space size
    pvd += bytes(32)         # unused
    pvd += both_endian_16(1)  # volume set size
    pvd += both_endian_16(1)  # volume sequence number
    pvd += both_endian_16(SECTOR)  # logical block size
    pvd += both_endian_32(0)  # path table size (no path table content)
    pvd += struct.pack("<I", 0)  # L path table location
    pvd += struct.pack("<I", 0)  # optional L path table
    pvd += struct.pack(">I", 0)  # M path table location
    pvd += struct.pack(">I", 0)  # optional M path table
    pvd += root_rec          # root directory record (34 bytes)
    pvd += strA("", 128)     # volume set identifier
    pvd += strA("DREAM-SERPENT-TESTGUEST", 128)  # publisher
    pvd += strA("", 128)     # data preparer
    pvd += strA("MKSEED.PY", 128)  # application
    pvd += strA("", 37)      # copyright file id
    pvd += strA("", 37)      # abstract file id
    pvd += strA("", 37)      # bibliographic file id
    pvd += dec_datetime()    # creation
    pvd += dec_datetime()    # modification
    pvd += dec_datetime()    # expiration
    pvd += dec_datetime()    # effective
    pvd.append(1)            # file structure version
    pvd.append(0)            # unused
    pvd += bytes(512)        # application use
    pvd += bytes(653)        # reserved
    pvd = pad_sector(bytes(pvd))
    assert len(pvd) == SECTOR, len(pvd)

    # --- Volume Descriptor Set Terminator ---
    term = bytearray()
    term.append(255)
    term += b"CD001"
    term.append(1)
    term = pad_sector(bytes(term))

    # --- Assemble the full image ---
    img = bytearray()
    img += b"\x00" * (SECTOR * 16)  # system area (LBA 0..15)
    img += pvd                      # LBA 16
    img += term                     # LBA 17
    img += root_dir                 # LBA 18
    for nm, data, flba, length in placed:
        # Defensive: ensure we are at the file's declared extent.
        assert len(img) // SECTOR == flba, (len(img) // SECTOR, flba)
        img += pad_sector(data)

    with open(out_path, "wb") as f:
        f.write(img)
    return len(img)


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(
            "usage: mkseed.py <out.iso> <name>=<path> [<name>=<path> ...]\n"
        )
        return 2
    out = argv[1]
    files = []
    for spec in argv[2:]:
        if "=" not in spec:
            sys.stderr.write("bad spec (need name=path): %s\n" % spec)
            return 2
        name, path = spec.split("=", 1)
        with open(path, "rb") as fh:
            data = fh.read()
        files.append((iso_name(name), data))
    # Deterministic order: sort by on-disk name.
    files.sort(key=lambda t: t[0])
    size = build(out, files)
    sys.stderr.write("mkseed: wrote %s (%d bytes, %d sectors)\n" % (out, size, size // SECTOR))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
