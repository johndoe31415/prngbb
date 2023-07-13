#!/usr/bin/env python3
#	prngbb - PRNG bounded buffer writes for persistence atomicity analysis
#	Copyright (C) 2023-2023 Johannes Bauer
#
#	This file is part of prngbb.
#
#	prngbb is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	prngbb is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with prngbb; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import sys
import struct
import hashlib
from FriendlyArgumentParser import FriendlyArgumentParser, baseint_unit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def determine_alignment(value):
	c = 1
	while True:
		if value % (1 << c):
			return 1 << (c - 1)
		c += 1

parser = FriendlyArgumentParser(description = "Evaluate bounded-buffer crypto device.")
parser.add_argument("-o", "--offset", metavar = "bytes", type = baseint_unit, default = "0", help = "Offset to seek to. Defaults to %(default)s.")
parser.add_argument("-l", "--length", metavar = "bytes", type = baseint_unit, default = "1 Mi", help = "Length of buffer. Defaults to %(default)s.")
parser.add_argument("-s", "--seed", metavar = "seed", default = "0", help = "PRNG seed. Defaults to '%(default)s'.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("dev", help = "Device that was written to.")
args = parser.parse_args(sys.argv[1:])

key = hashlib.md5(args.seed.encode()).digest()
if args.verbose >= 1:
	print(f"Offset {args.offset:#x}, length {args.length:#x}, key {key.hex()}")

invalid_cnt = 0

block_struct = struct.Struct("< Q Q")
cipher = Cipher(algorithms.AES(key), modes.ECB())
decryptor = cipher.decryptor()
prevctr = None
invalid = False

with open(args.dev, "rb") as f:
	f.seek(args.offset)
	for i in range(args.length // 16):
		foffset = args.offset + 16 * i
		block = f.read(16)
		plain = decryptor.update(block)
		(bcnt, bid) = block_struct.unpack(plain)
		if bid != 0:
			invalid_cnt += 1
			if (not invalid) or (args.verbose >= 2):
				print(f"Invalid block at {args.offset + 16 * i:#x} (alignment {determine_alignment(foffset)} bytes)")
			prevctr = None
			invalid = True
		else:
			invalid = False
			if prevctr is None:
				print(f"Initial block ID: {bcnt}")
			elif prevctr + 1 != bcnt:
				gap_size = abs(prevctr - bcnt + 1) * 16

				if (gap_size != args.length) or (args.verbose >= 2):
					print(f"Discontinuity at {foffset:#x} (alignment {determine_alignment(foffset)} bytes), previous count {prevctr} followed by {bcnt}, gap {gap_size} bytes = {gap_size // 1024 // 1024} MiB")
				if gap_size == args.length:
					print(f"Expected wraparound at {foffset:#x} (alignment {determine_alignment(foffset)} bytes)")
			prevctr = bcnt

print(f"{invalid_cnt} invalid blocks found.")
