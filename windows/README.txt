par3cmdline is a PAR3 compatible file verification and repair tool.

To see the ongoing development see:
https://github.com/parchive/par3cmdline



This is for testing usage only.
The implementation may be change largely.
Though I tried to follow the style of par2cmdline,
some options or behavior or output text may be different.

This is under construction.
There is basic feature only.
Some commands and options are useless.
There may be some mistake or failure.

It keeps all input blocks on memory at this time.
So, it cannot treat large files now.

It can create Index File and Archive Files.
Index File includes all types of packets without duplication.
Archive Files include Data Packets, which is a piece of input files.

It cannot create Recovery Files yet.
It cannot Verify nor Repair yet.





Usage:
  par3 -h  : show this help
  par3 -V  : show version
  par3 -VV : show version and copyright

  par3 t(rial)  [options] <PAR3 file> [files] : Try to create PAR3 files
  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files
  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file
  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files

Options: (all uses)
  -B<path> : Set the basepath to use as reference for the datafiles
  -v [-v]  : Be more verbose
  -q [-q]  : Be more quiet (-q -q gives silence)
  --       : Treat all following arguments as filenames
Options: (create)
  -s<n>    : Set the Block-Size (don't use both -b and -s)
  -r<n>    : Level of redundancy (%%)
  -c<n>    : Recovery Block-Count (don't use both -r and -c)
  -f<n>    : First Recovery-Block-Number
  -u       : Uniform recovery file sizes
  -l       : Limit size of recovery files (don't use both -u and -l)
  -n<n>    : Number of recovery files (don't use both -n and -l)
  -R       : Recurse into subdirectories
  -D       : Store Data packets
  -d<n>    : Enable deduplication of input blocks
  -abs     : Enable absolute path
  -C<text> : Set comment



[ About "trial" command ]

 If you want to see how PAR3 files will be created, use this command.
It tries to create PAR3 files, but won't write created data on files really.
It's useful to see file size or how many files.

 Though it doesn't write data, it reads file data for deduplication.
So, it may be slow for large files.

If you don't enable deduplication, it may be possible to trial without file reading.
At that time, Set ID is unknown.
But, I did not implement such feature yet.



[ About "-v" option ]

 When setting double -v -v, mapping of all blocks is shown.
If file size is large and there are many blocks,
output lines may be too many.
Use the option only for debug usage with small files.



[ About "-D" option ]

 If you wants to store source file data in PAR3 file, set this option.
It's silimar to non compressed archive file.
An archive file may contain some splitted pieces of source file.
The number of archive files and their size depend on options: -u, -l, -n<n>.
The name of archive files is like below;
something.part#+#.par3



[ About "-d<n>" option ]

 At this time, -d1 and -d2 are available.
Deduplication level 1 : same blocks of ordinary offset are be detected.
Deduplication level 2 : same blocks of varied offset are detected.
Be careful, comparing checksum of blocks is slow.
This may be useless for random data like compressed file.



[ About "-abs" option ]

 This option is risky. You should not set this normally.
By setting this, absolute path of files are stored in PAR3 files.



[ About "-C<text>" option ]

 When you want to include space in comment, cover the comment by "".
When you may set comment multiple times, they are joined with "\n" between each line.

Example of comment is like below;

-C"something like this"
-C"multi lines are ok."




