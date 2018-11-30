# immutableweb-core
Core project that implements file based streams for the Immutable Web

[![Build Status](https://travis-ci.com/immutableweb/immutableweb-core.svg?branch=master)](https://travis-ci.com/immutableweb/immutableweb-core)

For more details about the Immutable Web, check out: https://immutableweb.org

# Examples

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

# Goals & Background

This is an experimental project and at this point I have no idea where the project is going, if anywhere at all. For
a background on this project, please read the white paper at https://immutableweb.org . 

This repository is intended to act as a reference implementation of the Immutable Web concept. The main goal is to demonstrate
the capabilities of the system, establish best practices, review the overall concept, ensure it is cryptographically sound
and a whole host of other minor goals for establishing a new technology.

The goals of this system do not include speed, efficiency or even the greatest versatility. In the beginning all blocks
must be loaded to/from RAM, not the filesystem. Currently only one cryptographic toolkit is in use: The python Cryptography
module that implements the RSA algorithm. In the future a different crypography module should liekly be used. I like GNUPg and
Keybase.io, but the libraries for interfacing with GNUPg from python are... confusing. 

A key next step is to have someone competent with cryptography review this code. Are the blocks being chained correctly?
Is the structure sound? Is it implemented as envisioned? What best practices around cryptography should be implemented?

If you're a crypto geek, please let me know!


# Roadmap

Features & improvements I'd like to see:

* Support for GNUPg or even better, a plug-in system for different encryption packages. (Is that a good idea?)
* Support for reading/writing partial blocks from/to disk in order to enable writing large files wholes blocks do not into ram.
* Support for writing streams to S3, Google Drive and other cloud storage providers
