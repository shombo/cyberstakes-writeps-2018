## I'm So Meta Even This Acronym - Points: 350

### Prompt:

All of the files in this volume look innocuous. Maybe there's something deeper. Disk image: [disk.img.gz](./files/disk.img.gz)
### Hints:

 * It's always best to put things in order. 
 * It looks like there's some type of cryptography being used to obscure the hidden content.
 * Did you know the EXT filesystem supports ACLs?

### Solving:

For my first look at the challenge, I gunzip'd and copied a backup of the challenge. It's always a good idea to keep a known clean file and it's easier to keep it locally than to have to download a new one. 

```
gunzip disk.img.gz
cp disk.img disk.img.bak
```

Next, I poke around a little bit.
```
file disk.img
debugfs disk.img
```

It's an ext4 filesystem and the structure on disk is very similar to previous forensics challenges but there's a new directory: .hidden. I find this with the following debugfs commands:

```
debugfs disk.img
#ls
 2  (12) .    2  (12) ..    11  (20) lost+found    12  (16) archives   
 7321  (12) bin    183  (24) document1.pdf    184  (24) document1.txt   
 185  (24) document2.pdf    186  (24) document2.rtf   
 187  (24) document3.pdf    188  (24) document3.txt   
 189  (28) doc_within_doc.doc    190  (32) docx_within_docx.docx   
 191  (24) iwork_09.pages    192  (24) keynote_09.key   
 193  (20) myfile22.zip    194  (32) myfilegzip2.txt.gz.0.gz   
 195  (28) myfilegzip.txt.gz    196  (20) myfile.zip   
 197  (28) numbers_09.numbers    198  (28) ppt_within_doc.doc   
 199  (32) pptx_within_docx.docx    200  (20) testfile.doc   
 201  (24) testfile_pdf.pdf    202  (24) testfilex.docx   
 203  (24) testfilex.pdf    204  (24) workbook1.xls   
 205  (24) workbook2.xlsx    206  (28) xls_within_doc.doc   
 207  (32) xlsx_within_docx.docx    7322  (312) .hidden   

cd .hidden
ls
 7322  (12) .    2  (12) ..    7323  (12) 0    29306  (12) 1    7356  (12) 2   
 43927  (12) 3    43943  (12) 4    43951  (12) 5    43955  (12) 6   
 43957  (916) 7   
```

That directory is interesting. let's mount the directory and dig deeper:

``` 
mkdir mountpoint
sudo mount -o ro disk.img mountpoint #readonly
find mountpoint/.hidden -type f | wc -l
#output: 32769
```
There are almost 33k files in the hidden directory so we are going to have find a way to filter them.

Let's look at the hints. The first two aren't quite relevant yet but the third one sounds interesting. I've never worked with Linux extended ACL before so I [read up on it a bit](https://wiki.archlinux.org/index.php/Access_Control_Lists). 

It looks like there's a command `getfacl` that can read extended ACLs. I test it out on the file itself just to see what the output looks like:

```
#getfacl disk.img
# file: disk.img
# owner: owner
# group: owner
user::rw-
group::rw-
other::r--
```

I'll poke around the filesystem and see if anything has odd ACLs:
```
cd mountpoint
sudo find -exec getfacl {} \; > ../log
```

I opened the log file in vim and started scrolling through it looking for interesting things. Most lines looked like this:
```
# file: .hidden/1/4/7/6a
# owner: root
# group: root
user::rw-
group::r--
other::r--
```

But paging through it a bit, I noticed one that looks like this:
```
# file: .hidden/1/4/7/af
# owner: root
# group: root
user::rw-
user:712589474:-w-
group::r--
mask::rw-
other::r--
```

I wanted to quickly filter for similar lines so I threw a few quick lines into vim. The first filters out any line with "user::" in it, while the second searches for any remaining lines that still have "user:" in the line. In effect, this filters only for lines with data in between the colons in the line "user:datahere:"
```
:%s/user:://g
/user:
```

Tabbing through the results a bit, I came across this line: 
```
user:18804:--x
user:16787315:rwx
user:33562724:-wx
user:50356590:rwx
user:67135333:rw-
user:83915375:-wx
user:100693363:rwx
user:117448820:-wx
user:134246176:-w-
user:151021423:--x
user:167780449:r--
user:184577135:--x
user:201354853:rw-
user:218112288:rwx
user:234902625:-wx
user:251685733:-wx
user:268443764:r--
user:285239401:r-x
user:302019374:-w-
user:318775361:rwx
user:335562067:--x
user:352345925:r-x
user:369115970:--x
user:385884243:-wx
user:402669899:--x
user:419450199:rwx
user:436227145:r--
user:453003851:rwx
user:469779791:-wx
user:486559045:-wx
user:503333967:rw-
user:520114688:-wx
group::r--
mask::rwx

```

For those curious, we are seeing userids in that field and permissions (chmod) settings. That's 4 bytes per entry in the user id and an additional 3 bits for the permssions. I started pulling out individual bytes from the userid and converting them in python manually just to test if it was straight ascii:

```
>>> hex(int("18804",10))[2:].decode("hex")
'It'
>>> hex(int("16787315",10))[2:].zfill(8).decode("hex")
"\x01\x00's"
>>> hex(int("33562724",10))[2:].zfill(8).decode("hex")
'\x02\x00 d'
>>> hex(int("50356590",10))[2:].zfill(8).decode("hex")
'\x03\x00an'
# int("50356590",10) -> convert string to base10 int
# hex()[2:] -> convert int to string of format "0xXXX", trimming off the "0x"
# .zfill(8) -> padd odd-length hex strings with a zero
# .decode("hex") -> decode the hex string into bytes
```

As we can see, this starts to spell out something. So far we have `It's dan`

After I got tired of manually doing this I scripted something quick to parse it for me. The final version of that script is included in the files as `solve.py`

The full output in this entry is: `It's dangerous to go alone! Take this. AES_ECB SAKMWLIJKEOMEDOR`

So at this point we know that we are looking at AES_ECB and we have some weird string that is 16 characters long. After googling real quick [Wikipedia tells us](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) that AES_ECB is a weak form of encryption. The key is reused without an IV or a nonce in each block. Patterns in the original data can leak through. As it would turn out, the version of the cipher isn't really relevant in this instance but for the sake of discussion, don't use AES_ECB. 

We know something is encrypted in AES_ECB and we have the 16 bit key. Great! 

Now we just need some ciphertext to decrypt.

Looking back at the other files in the hidden directory, we see that there are other entries that have data hidden in the user field:
```
# file: .hidden/0/1/2/3/4/5/6/7/06
# owner: root
# group: root
user:4055737610:rwx
group::r--
mask::rwx
--
# file: .hidden/0/1/2/3/5/6/7/d1
# owner: root
# group: root
user:1982253623:--x
group::r--
mask::r-x
--
# file: .hidden/0/3/4/7/15
# owner: root
# group: root
user:751075054:rw-
group::r--
mask::rw-
--
# file: .hidden/0/3/5/6/7/e5
# owner: root
# group: root
user:2515692352:r--
group::r--
mask::r--
--
# file: .hidden/1/2/3/4/6/7/4b
# owner: root
# group: root
user:684872194:-w-
group::r--
mask::rw-
--
# file: .hidden/1/2/3/7/be
# owner: root
# group: root
user:3745167644:-w-
group::r--
mask::rw-
--
# file: .hidden/1/2/4/6/7/26
# owner: root
# group: root
user:711477825:--x
group::r--
mask::r-x
--
# file: .hidden/1/4/5/6/7/e9
# owner: root
# group: root
user:4269383359:r-x
group::r--
mask::r-x
--
# file: .hidden/1/4/6/7/11
# owner: root
# group: root
user:3198772061:-wx
group::r--
mask::rwx
--
# file: .hidden/1/4/7/af
# owner: root
# group: root
user:712589474:-w-
group::r--
mask::rw-
--
# file: .hidden/2/3/5/6/7/59
# owner: root
# group: root
user:3512131239:-wx
group::r--
mask::rwx
--
# file: .hidden/2/4/5/6/7/b1
# owner: root
# group: root
user:1535703584:r--
group::r--
mask::r--
```



There are 12 additional entries with 4 bytes each in the user ID field and an additional 3 bits in the permission field. At this point I don't know if the permissions field has relevant data or if it's just a distraction. We know the key is 16 bytes so I probably need to find a data length that is a multiple of 16. 

12 * 4 % 16 = 48 % 16 = 0. So we know that with 12 entries and just the 4 bytes per entry, we get a ciphertext that is an appropriate length for the key. 

Not wanting to write my own crypto from scratch, I found [this](https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41) example of AES_ECB. 

With a key, algorithm and ciphertext in hand, I just need to try to decrypt. I pulled out the ciphertext from the order as it was presented in the find output and tried that, but I couldn't get a legible plaintext. I tried alphabetical order, both forwards and backwards. I also tried using the permission bits as a sorting order as well but still couldn't get a plaintext that made sense. 

At this point, it was around 3am so I called it a night and came back with fresh eyes the next day. 

The next morning in the shower before work it occurred to me that I didn't check the [obvious] chronological sort time.

I did a quick ls on the entire structure to see what timestamps looked like. Most files had the exact same timestamp, so I filtered them out.

```
#find  -type f -exec ls -l {} \; | egrep -v "Dec  1"
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/7/af
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/5/6/7/e9
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/6/7/11
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/4/6/7/26
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/3/4/6/7/4b
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/3/7/be
-rw-r--r--+ 1 root root 0 Nov 25 10:47 .hidden/2/4/5/6/7/b1
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/2/3/5/6/7/59
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/0/1/2/3/4/5/6/7/06
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/0/1/2/3/5/6/7/d1
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/0/3/4/7/15
-rw-r--r--+ 1 root root 0 Nov 25 10:47 .hidden/0/3/5/6/7/e5
```

There are the same 12 files as before. So that confirms I have the right file. 
Let's look deeper into these files.

```
#stat .hidden/1/4/7/af .hidden/1/4/5/6/7/e9 .hidden/1/4/6/7/11 .hidden/1/2/4/6/7/26 .hidden/1/2/3/4/6/7/4b .hidden/1/2/3/7/be .hidden/2/4/5/6/7/b1 .hidden/2/3/5/6/7/59 .hidden/0/1/2/3/4/5/6/7/06 .hidden/0/1/2/3/5/6/7/d1 .hidden/0/3/4/7/15 .hidden/0/3/5/6/7/e5
  File: '.hidden/1/4/7/af'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 384         Links: 1
Access: (0664/-rw-rw-r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:40.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/1/4/5/6/7/e9'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 954         Links: 1
Access: (0654/-rw-r-xr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:38.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/1/4/6/7/11'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 994         Links: 1
Access: (0674/-rw-rwxr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:45.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/1/2/4/6/7/26'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 2039        Links: 1
Access: (0654/-rw-r-xr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:37.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/1/2/3/4/6/7/4b'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 3868        Links: 1
Access: (0664/-rw-rw-r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:44.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/1/2/3/7/be'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 4239        Links: 1
Access: (0664/-rw-rw-r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:42.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/2/4/5/6/7/b1'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 10158       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:46.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/2/3/5/6/7/59'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 12886       Links: 1
Access: (0674/-rw-rwxr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:43.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/0/1/2/3/4/5/6/7/06'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 20015       Links: 1
Access: (0674/-rw-rwxr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:36.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/0/1/2/3/5/6/7/d1'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 21242       Links: 1
Access: (0654/-rw-r-xr--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:01.000000000 -0500
Modify: 2018-11-25 10:47:41.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/0/3/4/7/15'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 30870       Links: 1
Access: (0664/-rw-rw-r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:02.000000000 -0500
Modify: 2018-11-25 10:47:35.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
  File: '.hidden/0/3/5/6/7/e5'
  Size: 0           Blocks: 2          IO Block: 1024   regular empty file
Device: 700h/1792d  Inode: 32614       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-12-01 21:20:02.000000000 -0500
Modify: 2018-11-25 10:47:39.000000000 -0500
Change: 2018-12-01 21:20:02.000000000 -0500
 Birth: -
```

As we can see, the seconds field on the modified timestamp differs with each file. Let's try sorting by time and seeing if we can get a decrypt.
```
#ls -lt  .hidden/1/4/7/af .hidden/1/4/5/6/7/e9 .hidden/1/4/6/7/11 .hidden/1/2/4/6/7/26 .hidden/1/2/3/4/6/7/4b .hidden/1/2/3/7/be .hidden/2/4/5/6/7/b1 .hidden/2/3/5/6/7/59 .hidden/0/1/2/3/4/5/6/7/06 .hidden/0/1/2/3/5/6/7/d1 .hidden/0/3/4/7/15 .hidden/0/3/5/6/7/e5
-rw-r--r--+ 1 root root 0 Nov 25 10:47 .hidden/2/4/5/6/7/b1
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/6/7/11
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/3/4/6/7/4b
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/2/3/5/6/7/59
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/3/7/be
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/0/1/2/3/5/6/7/d1
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/7/af
-rw-r--r--+ 1 root root 0 Nov 25 10:47 .hidden/0/3/5/6/7/e5
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/1/4/5/6/7/e9
-rw-r-xr--+ 1 root root 0 Nov 25 10:47 .hidden/1/2/4/6/7/26
-rw-rwxr--+ 1 root root 0 Nov 25 10:47 .hidden/0/1/2/3/4/5/6/7/06
-rw-rw-r--+ 1 root root 0 Nov 25 10:47 .hidden/0/3/4/7/15
```

I plug this order into [my script](./files/solve.py). 

```The flag is "ACI{ded4ee681a2ba4047d911063f97}"```

You can check out the script in ./files. There's a lot of remnants from when I found sorting orders that didn't work. 
