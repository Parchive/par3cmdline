par3cmdline is a PAR3 compatible file verification and repair tool.

To see the ongoing development see:
https://github.com/parchive/par3cmdline

The latest PAR3 specification is available at:
https://github.com/Parchive/par3cmdline/files/8318148/Parity_Volume_Set_Specification_v3.0.md


 I wrote this in C language for Visual C++ 2022 64-bit compiler.
You can compile this by Microsoft Visual Studio Community 2022.
Because this uses much memory, I support only 64-bit build on 64-bit OS.

 Because some features of gcc don't work on Windows OS,
I could not use MinGW (gcc for Windows).
(Such like UTF-8, file access, or GNU C runtime library.)


 This is for testing usage only.
The implementation may be changed largely.
Though I tried to follow the style of par2cmdline,
some options or behavior or output text may be different.

 This is under construction.
There is basic feature only.
Some commands and options are useless.
There may be some mistake or failure.
If it looks like freeze, push Ctrl+C key to cancel the task.

 It can create Index File and Archive Files.
Index File includes all types of packets without duplication.
Archive Files include Data Packets, which is a piece of input files.

 It can restore missing or damaged files by using Data Packets.
It can correct filename of misnamed files, when they were specified as extra files.

At this time, this supports Reed-Solomon Codes with Cauchy Matrix
and FFT based Reed-Solomon Codes by Leopard-RS library.

It doesn't use maultiple Recovery Codes at once.
It doesn't support "PAR inside" feature yet.



Usage:
  par3 -h  : Show this help
  par3 -V  : Show version
  par3 -VV : Show version and copyright

  par3 tc       [options] <PAR3 file> [files] : Try to create PAR3 files
  par3 te       [options] <PAR3 file> [file]  : Try to extend PAR3 files
  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files
  par3 e(xtend) [options] <PAR3 file> [file]  : Extend PAR3 files
  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file
  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files
  par3 l(ist)   [options] <PAR3 file>         : List files in PAR3 file
  par3 ti       [options] <ZIP file>          : Try to insert PAR in ZIP file
  par3 i(nsert) [options] <ZIP file>          : Insert PAR in ZIP file
  par3 d(elete) [options] <ZIP file>          : Delete PAR from ZIP file
  par3 vs       [options] <ZIP file>  [files] : Verify itself
  par3 rs       [options] <ZIP file>  [files] : Repair itself

Options: (all uses)
  -B<path> : Set the base-path to use as reference for the datafiles
  -v [-v]  : Be more verbose
  -q [-q]  : Be more quiet (-q -q gives silence)
  -m<n>    : Memory to use
  --       : Treat all following arguments as filenames
  -abs     : Enable absolute path
Options: (verify or repair)
  -S<n>    : Searching time limit (milli second)
Options: (create)
  -b<n>    : Set the Block-Count
  -s<n>    : Set the Block-Size (don't use both -b and -s)
  -r<n>    : Level of redundancy (percentage)
  -rm<n>   : Maximum redundancy (percentage)
  -c<n>    : Recovery Block-Count (don't use both -r and -c)
  -cf<n>   : First Recovery-Block-Number
  -cm<n>   : Maximum Recovery Block-Count
  -u       : Uniform recovery file sizes
  -l       : Limit size of recovery files (don't use both -u and -l)
  -n<n>    : Number of recovery files (don't use both -n and -l)
  -R       : Recurse into subdirectories
  -D       : Store Data packets
  -d<n>    : Enable deduplication of input blocks
  -e<n>    : Set using Error Correction Codes
  -i<n>    : Number of interleaving
  -fu<n>   : Use UNIX Permissions Packet
  -ff      : Use FAT Permissions Packet
  -lp<n>   : Limit repetition of packets in each file
  -C<text> : Set comment



[ About "create" command ]

 You may use "wild card" matching to specify names of input files or directories.
Be careful to set both "-R" and "*", because all files and directories will be listed.
It may be safe to use partial wild card like "*.txt".
Filename may include sub-directory, like "zipfolder/*.zip".



[ About "try to create" command ]

 If you want to see how PAR3 files will be created, use this command.
It tries to create PAR3 files, but won't write created data on files really.
It's useful to see file size or how many files.

 Though it doesn't write data, it reads file data for deduplication.
So, it may be slow for large files.
If you don't enable deduplication, it's possible to trial without file reading.
At that time, InputSetID is unknown.



[ About "extend" command ]

 When you want to create more recovery blocks for a given PAR3 set, use this command.
Instead of setting names of input files, set one PAR filename.
It verifies input files and creates compatible recovery blocks.
All input files must be complete, or else it will fail.
When you set wrong option, it may fail by compatibility issue.

 It will over-write existing PAR files.
If you want to create new PAR3 files in different base name, set a name of refered PAR file.

 If you set the max number of recovery blocks at the first creating time,
you won't be able to extend recovery blocks beyond the limit.



[ About "list" command ]

 If you want to see content in a PAR3 file, use this command.
It checks your specified PAR3 file, and shows how are packets.
When there are not enough packets in the PAR3 file, it will fail.

 This is listing internal information only.
It doesn't check files or directory tree really.
It may be useful to check a PAR3 file is valid.

 You may see BLAKE3 hash value of input files by setting "-v" option.
Though I (Yutaka Sawada) suggested to make a packet for additional hash values,
there is no official definition yet.
If many users request, I will add optional packets in future.



[ About "verify" command ]

 Verification requires memory of double block size.
When there isn't enough free memory, it will show error.

 You may specify extra files after PAR3 filename.
They are PAR3 files or misnamed (and/or damaged) input files.
These files must exist under base-path or current directory when base-path isn't set.
If you add PAR3 file (extension with .par3), the file will be verified as PAR3 file.
If you add other type files, they will be verified as input files.



[ About "repair" command ]

 Even when there are not enough blocks to repair all files,
it may try to repair as possible as it can.
When it could not reapir any files at all, this command returns RET_REPAIR_NOT_POSSIBLE(2).
When it reapired some files, this command returns RET_REPAIR_FAILED(5).



[ About "insert PAR" command ]

 This is a sample implementation of "PAR inside ZIP" feature.
This command inserts PAR3 packets in normal ZIP (.zip) or 7-Zip (.7z) file.
Because it doesn't modify the original ZIP file data,
other ZIP archiver tools can treat the protected ZIP file.

 To make simpler recovery record, it will select block size automatically.
You may set your favorite redundancy.
When you don't set redundancy, it becomes 1% by default.



[ About "delete PAR" command ]

 This is a sample implementation of "PAR inside ZIP" feature.
This command deletes PAR3 packets from protected ZIP (.zip) or 7-Zip (.7z) file.
The resulting ZIP file should be same as the original one.
If protected ZIP file is damaged, you must repair it before deleting PAR3 packets.



[ About "verify itself" command ]

 This is a sample implementation of "PAR inside ZIP" feature.
You can specify protected ZIP file as PAR file.
You may specify extra files in addition to the ZIP file,
if it was splitted into multiple pieces.

 Be careful, it verifies protected data only.
It cannot detect damage of unprotected data (PAR3 packets themselves).
If too many PAR3 packets are lost, it may not be able to verify itself.



[ About "repair itself" command ]

 This is a sample implementation of "PAR inside ZIP" feature.
You can specify protected ZIP file as PAR file.
It will repair damaged ZIP file and copy complete PAR3 packets.
So, repaired ZIP file is protected again.

 If you use normal "repair" command for "PAR inside ZIP",
it will erase PAR3 packets in the ZIP file.
Then, the repaired ZIP file won't be protected anymore.
So, you should use "repair itself" command for "PAR inside ZIP".



[ About specifying "PAR3 file" and "files" ]

 If you wish to create PAR3 files for a single source file,
you may leave out the name of the PAR3 file from the command line.
par3cmdline will then assume that you wish to base the filenames
for the PAR3 files on the name of the source file.

 You may also leave off the .par3 file extension when verifying and repairing.



[ About "-v" option ]

 By setting "-v", it may show more detail information.
When setting double "-v -v" or "-vv", it may show debug information.

When setting triple "-v -v -v" or "-vvv", it will show information of all blocks.
If file size is large and there are many blocks, output lines may be too many.
Use this option only for debug usage with small files.



[ About "-B" option ]

 When you want to include sub-directories in input files/directories,
you should set their base-path by "-B" properly.
If you specify PAR3 file as an absolute path and don't set base-path by "-B",
its parent directory will be the base-path automatically.
If you specify PAR3 file as a relative path and don't set base-path by "-B",
current working directory will be the base-path automatically.



[ About "-q" option ]

 By setting "-q", it may show less information.
When setting double "-q -q" or "-qq", it stops output.
At that time, you may refer return value to know result.



[ About "-m" option ]

 If you want to limit using memory size, set this option.
You may set last character to "k", "kb", "m", "mb", "g", or "gb" as unit.
The unit characters are case insensitive.
For example, setting "-m1MB" is same as "-m1048576".

 Note, this is not strict value. It may use more memory.
When this isn't set, it assumes unlimited RAM size.

 This option will affect some buffer size.
Mostly the buffer for file access, such like Input Files or PAR files.
You should set larger value than block size.
The limit adapts each buffer size independently, instead of total size.

 This doesn't affect required memory of fixed size.
Such like, memory for one Block or Matrix.
For example, it may consume memory for a few blocks,
even when you set less limit size.
Furthermore, 16-bit Reed-Solomon Codes may consume max 2 GB memory for matrix at repair.



[ About "-abs" or "-ABS" option ]

 This option is risky. You should not set this normally.
By setting this, absolute path of files are stored in PAR3 files at creation.
At verification, directory tree is treated as relative path by default.
Only when you set "-abs" option, included absolute path becomes enabled.
When a PAR3 file doesn't include absolute path, "-abs" option is ignored.

 "-ABS" option is available on Windows OS only.
This includes a drive letter in absolute path at creation.
When a drive letter isn't included in a PAR3 file,
it will refer the current drive.

 At verification, "-abs" and "-ABS" are different behavior to search extra files.
When "-abs" is set, base-path for extra files doen't include a drive letter.
When "-ABS" is set, base-path for extra files includes a drive letter.
If you don't specify extra files nor base-path, "-abs" and "-ABS" are same.



[ About "-S<n>" option ]

 When searching slices is very slow, it may look like freeze.
So there is a time limit in searching loop.
Normally, you don't need to change behavior by this option.

 If you want to find more blocks in damaged files, set this option.
When you set -S1000, it will spend max 1000 (milli seconds) per block.
The default value is 100 ms per each block size.
Because it may search 2 times per each block size, it may be double time.

 Be careful to set large value.
If you set -S1000 for a damaged file of 2000 blocks,
it will consume max 4000 seconds. (2000 * 1000 * 2 = 4000,000 ms)
4000 seconds are 66 minutes. You may need to wait so long.



[ About "-b" option ]

 Though you can specify a preferable number of blocks,
the result may be different from the specified block count.
It's difficult to predict arrangement of blocks.
Number of input files, tail packing, and deduplication will affect.



[ About "-c" option ]

 As written above, specifying Block-Count will differ to actual number.
Thus, specifying Recovery Block-Count will differ to result, too.
It may be difficult to predict actual numbers.



[ About "-cf" option ]

 It's possible to set the First Recovery-Block-Number.
Insert "f" between "-c" and <number>, then the option is -cf<n>.



[ About "-cm" option ]

 It's possible to set the maximum Recovery Block-Count.
Insert "m" between "-c" and <number>, then the option is -cm<n>.
This is important to make compatible PAR3 files with FFT based Reed-Solomon Codes.
If the value is different, their recovery blocks may be unavailable each other.
Be careful to set this value. No need to set mostly.



[ About "-r" option ]

 This redundancy percent is against the number of input blocks.
It's possible to set a value in range from 1% to 250%.
Be careful that the redundancy isn't against input file size.
When deduplication is enabled, there may be fewer input blocks.

 For example, there may be a file of same bytes.
Even when the file is large, the uniform bytes gives only two blocks.
They are duplicated full size slice and the last tail slice.
In this case, 100% redundancy will create only 2 recovery blocks.

 To solve this problem, par2cmdline has "-rk", "-rm", or "-rg"  options.
I will implement them in future.



[ About "-rm" option ]

 It's possible to set the maximum redundancy.
Insert "m" between "-r" and <number>, then the option is -rm<n>.
This is important to make compatible PAR3 files with FFT based Reed-Solomon Codes.
If the value is different, their recovery blocks may be unavailable each other.
Be careful to set this value. No need to set mostly.



[ About "-l" option ]

 It's possible to limit size of creating recovery files.
By setting "-l", each recovery files will be smaller than the max input file.
If packet and/or block size are large, it may not become smaller.
You may set exact size after "-l", such like "-l2147483648". 
The following number becomes limit size (bytes).



[ About "-D" option ]

 If you wants to store source file data in PAR3 file, set this option.
It's silimar to non compressed archive file.
An archive file may contain some splitted pieces of source file.
The number of archive files and their size depend on options: "-u", "-l", "-n<n>".
The name of archive files is like below;
something.part#+#.par3



[ About "-d<n>" option ]

 At this time, "-d1" and "-d2" are available.
Deduplication level 1 : same blocks of ordinary offset are be detected.
Deduplication level 2 : same blocks of varied offset are detected.
Be careful, comparing checksum of blocks is slow.
This may be useless for random data like compressed file.



[ About "-e<n>" option ]

 At this time, "-e1" and "-e8" are available.
"-e1" is Cauchy Reed-Solomon Codes. This is the default now.
"-e8" is FFT based Reed-Solomon Codes by Leopard-RS library.



[ About "-i<n>" option ]

 To support many blocks at FFT based Reed-Solomon Codes,
I test interleaving method.
Though I implemented the basic mechanism, it's still under construction.
Note, the value is ignored at Cauchy Reed-Solomon Codes.



[ About "-fu<n>" option ]

 You may use UNIX Permissions Packet to store meta data of files and/or directories.
At this time, this supports only two fields: mtime and i_mode.
Another PAR3 client may support other fields.

 The number after "-fu" is bitwise or.
If you omit number, it stores all values.
"-fu1" : mtime only
"-fu2" : i_mode only
"-fu3" : both mtime and i_mode
"-fu4" : store/recover options of directory
"-fu" or "-fu7" : all fields of all files and directories

 Causion about permissions (-fu2 option).
You may not repair files, when there isn't write permission.
I cannot test behavior on Linux OS.
It may be safe to store/recover mtime only (-fu1 option).

 Causion about directories (-fu7 option).
You cannot change permissions of directories on Windows OS.
You may not modify mtime of directories on Windows OS.
I don't know how it works on Linux OS.



[ About "-ff" option ]

 You may use FAT Permissions Packet to store meta data of files.
At this time, this supports only one field: LastWriteTime.

 Because Microsoft C-runtime library doesn't support FileAttributes nor directory,
you cannot store/recover them in par3cmdline.
Another PAR3 client may support other fields or directory.



[ About "-lp<n>" option ]

 You may limit repetition of packets in each PAR file.
It will repeat critical packets by number of included blocks like below.

Redundancy of critical packets;
number of blocks = 0 ~ 1 : number of copies = 1
number of blocks = 2 ~ 3 : number of copies = 2
number of blocks = 4 ~ 7 : number of copies = 3
number of blocks = 8 ~ 15 : number of copies = 4
number of blocks = 16 ~ 31 : number of copies = 5
number of blocks = 32 ~ 63 : number of copies = 6
number of blocks = 64 ~ 127 : number of copies = 7
number of blocks = 128 ~ 255 : number of copies = 8
number of blocks = 256 ~ 511 : number of copies = 9
number of blocks = 512 ~ 1023 : number of copies = 10
number of blocks = 1024 ~ 2047 : number of copies = 11
number of blocks = 2048 ~ 4095 : number of copies = 12
number of blocks = 4096 ~ 8191 : number of copies = 13
number of blocks = 8192 ~ 16383 : number of copies = 14
number of blocks = 16384 ~ 32767 : number of copies = 15
number of blocks = 32768 ~ 65535 : number of copies = 16

 If you want to make smaller PAR files, you should set this option.
When there are some PAR files, setting "-lp3" would be enough.
The option puts packets at the top, in middle, and at the end of a PAR file.



[ About "-C<text>" option ]

 When you want to include space in comment, cover the comment by "".
When you set comment multiple times, they are joined with "\n" between each line.

Example of comment is like below;

-C"something like this"
-C"multi lines are ok."


