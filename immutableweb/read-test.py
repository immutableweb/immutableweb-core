#!/usr/bin/env python

from stream import Stream

s = Stream("public sig")
s.open("test.im")
s.set_stream_signature_keys("public sig")

block_index = 1
while True:
    block = s.read_block(block_index)
    if not block:
        break
    print "%d: %s" % (block_index, block)
    block_index += 1

s.close()
