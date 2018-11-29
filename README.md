# immutableweb-core
Core project that implements streams for the Immutable Web

[![Build Status](https://travis-ci.com/immutableweb/immutableweb-core.svg?branch=master)](https://travis-ci.com/immutableweb/immutableweb-core)

Currently there is no code written for this project yet -- I'm looking for feedback on the concept. Should the concept be deemed worthy, I'll work to create an initial implementation.

If you think the Immutable Web is viable and you have identified a problem or have a suggestion that improves the concept, please create an issue for this project.

## Creating your first stream

```
from immutableweb import stream
from immutableweb import crypto

s = stream.Stream()
s.set_stream_signature_keys(crypto.make_key_pair())
s.create("test.im")
s.append(content=b"Block content!")
s.close()
```
