# Admin Access? Sign me up! - Points: 125

### Description:

We have discovered a service running at challenge.acictf.com:20261 that gives out authentication keys. However, we don't seem to be able to get anywhere without admin access. Can you help? Source code: [signer.py](src/signer.py).

### Hints

 - None

### Solution

After looking at the signer script for a little bit, it appears that some secret is added to our list of usernames, then that is hashed. We need the hashed value of a list of usernames that contains the user `admin`.

This seems tough. However, due to the fact that the secret is *prepended* to the data, this signer mechanism is vulnerable to a [hash length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack).

Using [hashpump](https://github.com/bwall/HashPump), we can easily get the hash that we need.

### Flag: `ACI{a813cb3c95d5f4821dcf06411ad}`

