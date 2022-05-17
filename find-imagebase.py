#!/usr/bin/python3
# calculate image base of PE to feed into ropfile filtering script
import sys
import struct

filename = sys.argv[1]
contents = b""
with open(filename, "rb") as f:
    contents = f.read()

# offset 0x3c to pe header
pe_offset = struct.unpack('I', contents[60:64])[0]

# imagebase location
imagebase = struct.unpack('i', contents[pe_offset + 0x34:pe_offset + 0x38])[0]

print('0x{:x}'.format(imagebase))

