# immutableweb-core
Core project that implements file based streams for the Immutable Web

[![Build Status](https://travis-ci.com/immutableweb/immutableweb-core.svg?branch=master)](https://travis-ci.com/immutableweb/immutableweb-core)

For more details about the Immutable Web, check out: https://immutableweb.org

Some sample code for creating and consuming IW streams:

## Creating a stream

```
from immutableweb import stream
from immutableweb import crypto

s = stream.Stream()
s.set_stream_signature_keys(crypto.make_key_pair())
s.create("test.im")
s.append(content=b"Block content!")
s.close()
```

## Verify stream and read all the blocks

```
from immutableweb import stream

with stream.Stream("test.im") as s:
    for i in range(1, s.verify()):
        print(s.read(i))  
```
