# Word Up - Points: ???

### Description:

<missing since site is down>

### Hints

<missing since site is down>

### Solution

So you are given an encrypted word document with the provided password `supersecret`. You can decrypt this document with [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool). See [extra](#extra) for how to do this if not given a password.

*Note* You can also simply open this document, enter the password, and save as .rtf. Then re-save as .docx to remove the encryption; however, this causes an issue since it changes the checksums where the flag is stored.

`msoffcrypto-tool -p supersecret word_up.docx word_up_decrypted.docx`

So a .docx is simply a container and can be unzipped.

`unzip word_up_decrypted.docx -d word_up_decrypted`

Looking through the files, you will notice a bunch of base64 encoded data in document.xml under `gfxdata`. I tried decoding this initially - it did not make sense. I looked into it more later and found [this post](https://social.msdn.microsoft.com/Forums/office/en-US/0fcedce7-0d2f-4e93-97e7-01c453d79e41/how-to-decode-gfxdata?forum=worddev). Essentially, gxfdata is a zip file (after you replace the `&#xA;` characters). You then unzip these 8 gfxdatas, and you will find the flag in gfxdata6.zip

`textCheckSum="ACI{6357a19840dc2be549ba4f3e0c1}" `


### Extra Word Stuff<a name="extra"></a>

#### Cracking Word Encryption Password

So the password is actually not required for this problem. Unsure what to do initially, I noticed there is a second password for editing the document (not opening it). I set about to decrypt this second password. I found that you can extract word hashes with [office2john](https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/office2john.py). Turns out, this is the wrong hash (its the encryption password again), but I wanted to document it anyways.

`python office2john.py word_up.docx > hash.txt`

[This document](http://pentestcorner.com/cracking-microsoft-office-97-03-2007-2010-2013-password-hashes-with-hashcat/) walks you through how to crack this hash. You need to remove the document name from the hash prior to cracking:
`:$office$*2010*100000*128*16*f3c7d48eebf7facaeeb26db3cfa3599b*447a2bf5c7cae66b46460e4c57c70c94*53f49bff3409a07e984825b7a9ae4b64a7ee0993dc2af82b6f983acef2012fef`

Then you can crack the hash with:

`hashcat -m 9500 hash.txt /usr/share/wordlists/rockyou.txt --username`

This simply recovers the password `supersecret` which we already knew.

####Removing edit password

Once decrypted, you will notice the document is still protected from being editing. I initially thought the flag might be in the tracked changes, so I set about removing this protection.

Looking at settings.xml after converting .docx to .zip and extracting, you will find the below information.

```
w:cryptProviderType="rsaAES"
w:cryptAlgorithmClass="hash"
w:cryptAlgorithmType="typeAny"
w:cryptAlgorithmSid="14"
w:cryptSpinCount="100000" w:hash="ppEhqcg6s7JEPNsEjVZlXI7z0OBaS8PlOpsKrOrmxBreHuUmjgaIOBWhA52D7LkKYY9txOTkdvjA3reoy9fbHw==" w:salt="EU0BNcL5nghjUDGQ1yzgMA=="
```

If you re-save this file as a .rtf and search the resulting document, you will find this password hash in the new .rtf.
`{\*\passwordhash 0200000078000000180000000e800000a08601004000000010000000280000006800000000000000a69121a9c83ab3b2443cdb048d56655c8ef3d0e05a4bc3e53a9b0aaceae6c41ade1ee5268e06883815a1039d83ecb90a618f6dc4e4e476f8c0deb7a8cbd7db1f114d0135c2f99e0863503190d72ce030
}`

The easy solution is simply to delete the entire password hash, resave as a .docx, and you can now see comments, tracking, etc. Turns out, this does nothing for this challenge but it might be useful in the future.

### Flag: `ACI{6357a19840dc2be549ba4f3e0c1}`
