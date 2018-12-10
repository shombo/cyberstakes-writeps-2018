Binary gives the abilities to allocate different creatures, put them in your party, etc.

The key is that you can allocate an unknown creature which consists of a large
buffer that we can read/write, but it also treats as a second creature. 

First, use a mostly blank second creature and train it -> leak addresses.
Use that to build a second creature with the appropriate function pointers
