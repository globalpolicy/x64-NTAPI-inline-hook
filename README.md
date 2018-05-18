# x64-NTAPI-inline-hook
A simple C program to perform inline NTAPI hooks
This is an update to an x86 version I wrote some years ago :
http://c0dew0rth.blogspot.com/2016/01/openprocess-api-hook-in-msvcc.html
While that one was aimed at patching kernel32 functions in x32 processes (OpenProcess to be particular), in this case, the code is targetting ntdll functions.
The reason for this is that I found kernel32 functions to be rather random with no specific pattern. There were jump thunks in some places and in some places, the function procedure started immediately. So, just to avoid having to use a disassembler engine, I went with ntdll functions, which were very well patterned.
This is nothing new but I still wanted to make a 64-bit hooker, so I did.
