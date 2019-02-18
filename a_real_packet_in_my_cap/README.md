# A Real Packet in my CAP

## Forensics - 200 points

### Description

A lot of interesting information is flying over the network! What can you
extract?

### Hints

- Start by looking through the packet capture for communcation streams
- There's more than one interesting stream in this pcap...
- Once you've found the first item of interest, keep looking until you find
  what to do with it!

### Solution

This challenge presents a packet capture file containing a variety of traffic.
The first step that I typically take with network forensic challenges is to
open the packet capture in [Wireshark](www.wireshark.org). I then select
`Statistics` -> `Protocol Hierarchy` from the menu. This gives a high-level
overview of the different types of protocols in the pcap so I can see if there
is anything unique or out of the ordinary from other similar network forensic
challenges. I immediately notice that there is IRC traffic. Given that this is
a CTF, I hone in on this traffic by filtering for only IRC traffic in
Wireshark. By following the TCP stream, we see a conversation between two
parties.

![IRC Conversation](irc_conversation.png)

So we have a key for a file, but we don't know which file the key unlocks! The
next step naturally is to find the file of interest. Going back into the
Protocol Hierarchy, we see a bunch of UDP, ARP, SSH, SSL, ICMP, and HTTP
traffic. Of these, the only one worth investigating for a file is HTTP.
Another simple HTTP filter in Wireshark shows a file is being downloaded called
`deaddrop`. Navigating to `File` -> `Export Objects` -> `HTTP` is the easiest
way to extract this file from the pcap.

`deaddrop` is an ELF 64-bit binary. Opening it up in Binary Ninja and
looking at the `main` function reveals that it can follow two basic execution
paths: `do_pickup` or `do_drop`. I felt that, since I already had the key, I 
just needed to do some basic RE to figure out which path to take, and pass my
key in correctly. `do_drop` calls `AES_CBC_encrypt_buffer`, while `do_pickup`
calls `AES_CBC_decrypt_buffer`. Therefore, `do_pickup` is probably the route
we want to take. By running `./deaddrop pickup <key>`, where `<key>` is the
key in the screenshot above, we get the flag.
