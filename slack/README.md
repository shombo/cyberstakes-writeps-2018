# Cut me some Slack - Points: 250

### Description:

We know there was a flag on this volume at some point... Disk image: disk.img.xz
(not included in repo, as it is large).

### Hints

This is a pretty cool python package: https://github.com/mrfalcone/pyext2
Man, the author left parts of the flag all over the place.
Sometimes the best parts are compressed.
The backup doesn't necessarily match the current version.

### Solution

Slack space refers to the extra space on disk between the end of a file and the
end of the last block for that file (as a instance of internal fragmentation).
In this problem, the slack for the main file and the backup differs in a number
of cases, containing a compressed archive of a single character of the flag.
This can noticed by the beginning bytes of the slack space of the main file
being the gzib header. Some futzing/guessing was needed to get everything to
decompress properly.

Disk image not included, as this repo is large enough already.

Thanks to the previously listed python repo for the support code.
