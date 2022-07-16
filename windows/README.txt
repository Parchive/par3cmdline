par3cmdline is a PAR3 compatible file verification and repair tool.

To see the ongoing development see:
https://github.com/parchive/par3cmdline

The latest PAR3 specification is available at:
https://github.com/Parchive/par3cmdline/files/8318148/Parity_Volume_Set_Specification_v3.0.md


 I wrote this in C language for Visual C++ 2019 64-bit compiler.
You can compile this by Microsoft Visual Studio Community 2019.
Because this uses much memory, I support 64-bit build only on 64-bit OS.

 Because some features of gcc don't work on Windows OS,
I could not use MinGW (gcc for Windows).
(Such like UTF-8, file access, or C runtime library.)


 This is for testing usage only.
The implementation may be change largely.
Though I tried to follow the style of par2cmdline,
some options or behavior or output text may be different.

 This is under construction.
There is basic feature only.
Some commands and options are useless.
There may be some mistake or failure.

 It can create Index File and Archive Files.
Index File includes all types of packets without duplication.
Archive Files include Data Packets, which is a piece of input files.

 It can restore missing or damaged files by using Data Packets.
It can correct filename of misnamed files, when they were specified as extra files.

At this time, this supports Reed-Solomon Codes with Cauchy Matrix.
I test FFT based Reed-Solomon Codes by Leopard-RS library.

It doesn't use maultiple Recovery Codes at once.
It doesn't support "PAR inside" feature yet.




Usage:
  par3 -h  : show this help
  par3 -V  : show version
  par3 -VV : show version and copyright

  par3 t(rial)  [options] <PAR3 file> [files] : Try to create PAR3 files
  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files
  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file
  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files
  par3 l(ist)   [options] <PAR3 file>         : List files in PAR3 file

Options: (all uses)
  -B<path> : Set the base-path to use as reference for the datafiles
  -v [-v]  : Be more verbose
  -q [-q]  : Be more quiet (-q -q gives silence)
  -m<n>    : Memory (in MB) to use
  --       : Treat all following arguments as filenames
  -abs     : Enable absolute path
Options: (verify or repair)
  -S<n>    : Searching time limit (milli second)
Options: (create)
  -s<n>    : Set the Block-Size (don't use both -b and -s)
  -r<n>    : Level of redundancy (%)
  -c<n>    : Recovery Block-Count (don't use both -r and -c)
  -u       : Uniform recovery file sizes
  -l       : Limit size of recovery files (don't use both -u and -l)
  -n<n>    : Number of recovery files (don't use both -n and -l)
  -R       : Recurse into subdirectories
  -D       : Store Data packets
  -d<n>    : Enable deduplication of input blocks
  -e<n>    : Set using Error Correction Codes
  -fu<n>   : Use UNIX Permissions Packet
  -C<text> : Set comment



[ About "create" command ]

 You may use "wild card" matching to specify names of input files or directories.
Be careful to set both "-R" and "*", because all files and directories will be listed.
It may be safe to use partial wild card like "*.txt".
Filename may include sub-directory, like "zipfolder/*.zip".



[ About "trial" command ]

 If you want to see how PAR3 files will be created, use this command.
It tries to create PAR3 files, but won't write created data on files really.
It's useful to see file size or how many files.

 Though it doesn't write data, it reads file data for deduplication.
So, it may be slow for large files.
If you don't enable deduplication, it's possible to trial without file reading.
At that time, InputSetID is unknown.



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
When it reapired some files, this command returns RET_REPAIR_FAILED(2).



[ About specifying "PAR3 file" and "files" ]

 If you wish to create PAR3 files for a single source file,
you may leave out the name of the PAR3 file from the command line.
par3cmdline will then assume that you wish to base the filenames
for the PAR3 files on the name of the source file.

 You may also leave off the .par3 file extension when verifying and repairing.



[ About "-v" option ]

 By setting "-v", it may show more detail information.
When setting double "-v -v" or "-vv", it may show debug information.
For example, mapping of all blocks is shown at creation.
If file size is large and there are many blocks, output lines may be too many.
Use the option only for debug usage with small files.



[ About "-q" option ]

 By setting "-q", it may show less information.
When setting double "-q -q" or "-qq", it stops output.
At that time, you may refer return value to know result.



[ About "-m" option ]

 If you want to limit using memory size, set this option.
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



[ About "-c" option ]

 It's possible to set the First Recovery-Block-Number.
Add "f" between "-c" and <number>, then the option is -cf<n>.

 It's possible to set the Max Recovery-Block-Count.
Add "m" between "-c" and <number>, then the option is -cm<n>.
Max Recovery-Block-Count is important to make compatible PAR3 files later.
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



[ About "-fu<n>" option ]

 You may use UNIX Permissions Packet to store file's meta data.
At this time, this supports only two fields: mtime and i_mode.
The number is bitwise or.
If you omit number, it stores all values.
"-fu1" : mtime only
"-fu2" : i_mode only
"-fu" or "-fu3" : both mtime and i_mode

 Causion about permissions (-fu2 option).
You may not repair files, when there isn't write permission.
I cannot test behavior on Linux OS.
It may be safe to store/recover mtime only (-fu1 option).



[ About "-C<text>" option ]

 When you want to include space in comment, cover the comment by "".
When you set comment multiple times, they are joined with "\n" between each line.

Example of comment is like below;

-C"something like this"
-C"multi lines are ok."




