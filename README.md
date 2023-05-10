## [bitcoin/libblkmaker](https://github.com/bitcoin/libblkmaker)

### Dependencies:

[Jansson 2.0](https://github.com/akheron/jansson/tree/v2.0) with 'long long' support

### Example dependencies:

[Jansson 2.1](https://github.com/akheron/jansson/tree/v2.1) (to read JSON from stdin)

[libgcrypt](https://github.com/gpg/libgcrypt) (for SHA256)

##### For usage, check out example.c.

**Run**: `make example` to build it.

**Note**:

You must assign `blkmk_sha256_impl` to a function pointer

```
bool mysha256(void *hash_out, const void *data, size_t datasz)
```

**`hash_out` must be able to overlap with data!**

Note that you should **NOT** roll ntime for data retrieved without explicitly
checking that it falls within the template's limitations (mintime, maxtime,
mintimeoff, and maxtimeoff).

**Read the [BIP 23](https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki) specification in detail to
understand how they work.**

It is usually best to simply get more data as often
as it is needed.

For `blkmk_get_mdata`, you may specify that you intend to roll
the ntime header exactly once per second past usetime - it will then set
[*out_expires](blkmaker.c) such that the expiration occurs before you roll beyond any ntime
limits.

If you are rolling ntime at any rate other than once per second, you should NOT specify `can_roll_ntime` to `blkmk_get_mdata`, and must check that your
usage falls within the explicit template limits yourself.
