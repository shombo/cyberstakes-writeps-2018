We are given the ability to allocate shirts/hats/etc.

First, we use a format string in shirts to leak appropriate base addresses

Then, for actual code exec:
The program keeps track of each slot with a an integer and a pointer, with the integer 
specifying the type of item. In one function, if we start with the integer as 20, it will
call a function pointer in the object (as if it was the shoe object). If we can get an
object with a buffer, such as a shirt, we can get code exec.

Due to the way the format string worked, we have a limited overwrite to the integer keeping
track of the type (due to the the layout of the format string, we only could write up to ~8,
from what I recall). Multiple rounds of freeing objects (and subracting off the type number)
allows us to get to the integer for code exec.
