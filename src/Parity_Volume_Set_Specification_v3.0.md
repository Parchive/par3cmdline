# Parity Volume Set Specification 3.0 [2022-03-21 ALPHA DRAFT]  

**Michael Nahas**

With ideas from **Yutaka Sawada**, **animetosho**, and **Markus Laire**.

*Based on Parity Volume Set Specification 2.0 [2003-05-11] by Michael Nahas with ideas from Peter Clements, Paul Nettle, and Ryan Gallagher*

*Based on Parity Volume Set Specification 1.0 [2001-10-14] by Stefan Wehlus, Tobias Reiper, Kilroy Balore, Willem Monsuwe, Karl Vogel, and Ryan Gallagher*

<!---
This file is in Github-Flavored Markdown.
(The original Markdown does not support tables)
On linux, it can be converted to HTML by "pandoc --from=gfm --to=html".
--->
<!--- Add borders to tables --->
<style>
table, th, td {
  border: 1px solid black;
}
</style>
<!---
History

Started January 16th, 2020
New Design, July 29th, 2021
Updated based on feedback November 16th, 2021  (dropped streaming, added chunks)
Updated November 26th, 2021  (complete, except for a few small details)
Updated December 6th, 2021  (Refining)
Updated December 30th, 2021  (Nearing draft version)
Updated January 28th, 2022  (Official "Pre-reference implementation" draft)
--->

**License:** The legal rights associated with this document are covered by the license in Appendix A. 

## Introduction

This document describes a file format for storing redundant data.  If any of the original data is damaged in storage or transmission, the redundant data can be used to regenerate the original input.  Of course, not all damages can be repaired, but many can.

## Table of Contents

- [Introduction](introduction)
- [Prerequisites](#prerequisites)
  - [Use Case](#use-case)
  - [Design Goals](#design-goals)
  - [The Math of Redundancy](#the-math-of-redundancy)
  - [Specifics of Computation](#specifics-of-computation)
- [File Layout](#file-layout)
  - [Conventions](#conventions)
  - [Packets](#packets)
    - [Packet Header](#packet-header)
    - [Creator packet](#creator-packet)
    - [Comment packet](#comment-packet)
    - [Start packet](#start-packet)
    - [Data Packet](#data-packet)
    - [External Data Packet](#external-data-packet)
    - [Matrix Packets](#matrix-packets)
      - [Cauchy Matrix Packet](#cauchy-matrix-packet)
      - [Sparse Random Matrix Packet](#sparse-random-matrix-packet)
      - [Explicit Matrix Packet](#explicit-matrix-packet)
    - [Recovery Data Packet](#recovery-data-packet)
    - [Recovery External Data Packet](recovery-external-data-packet)
    - [File Packet](#file-packet)
    - [Directory Packet](#directory-packet)
    - [Root Packet](#root-packet)
    - [File System Specific Packets](#file-system-specific-packets)
      - [Link Packet](#link-packet)
      - [UNIX Permissions Packet](#unix-permissions-packet)
      - [FAT Permissions Packet](#fat-permissions-packet)
- [Clarifications and Commentary](#clarifications-and-commentary)
  - [Security](#security)
  - [Order of Packets](#order-of-packets)
  - [Alignment](#alignment)
  - [Galois Field Encoding](#galois-field-encoding)
  - [Rolling Hash](#rolling-hash)
  - [Chunking and Deduplication](#chunking-and-deduplication)
  - [Compression](#compression)
  - [Sparse Matrices](#sparse-matrices)
  - [Incremental Backup](#incremental-backup)
  - [Par Inside Another File](#par-inside-another-file)
  - [Conventions](#conventions-1)
- [Conclusion](#conclusion)
- [Appendix A: License](#appendix-a-license)
- [Appendix B: Example Application-Specific Packet Type](#appendix-b-example-application-specific-packet-type)
- [Appendix C: Example of a Deduplication Algorithm.](#appendix-c-example-of-a-deduplication-algorithm)


## Prerequisites 

Before getting into the exact bytes of the file format, it is useful to cover how it will be used, the designer's goals, and the necessary math.

### Use Case

The user selects a set of files from which the redundant data is to be made.  These are known as "input files" and, together with their directory tree, are known as the "input set".  The user provides the input set to a program which generates new files that match the specification in this document.  The program is known as a "Parchive 3.0 client" or "client" for short.  The generated files are known as "Parchive 3.0 files" or "Par3 files" and usually have the extension ".par3".

If the files and directories in the input set ever get damaged (by being transmitted unreliably or stored on a faulty disk), a client can read the damaged input files, read the (possibly damaged) Par3 files, and regenerate the original input files and directory tree.  Again, not all damages can be repaired, but many can. 


### Design Goals

Parchive 3.0's goal is to provide a complete solution for the bottom two layers of archiving: redundancy and splitting.  ("Splitting" is the breaking of a single archive into multiple pieces that can be stored on separate disks or transmitted in separate network packets.)  Other layers of archiving --- like compression, encryption, and storing metadata --- may be better served by other programs (zip/gzip/7zip, pgp/gpg, tar, etc.)  Parchive 3.0 provides minimal support for some of these layers, for ease and backwards compatibility.

Parchive 3.0 does not provide any support for encryption, because it is tricky to do right.

Major differences from Parchive 2.0 are:
- support empty directories
- support more than 2^16 files
- support UTF-8 filenames (Par2 added this after version 2.0.)
- support file permissions
- support hard links and symbolic links
- support "incremental backups"
- support files that work both as a Par3 file and another type.  For example, putting recovery data inside a ZIP, ISO 9600 disk image, or other file.
- support for storing data inside a Par3 file (This was optional in Par2.)
- support any Galois field that is a power of 2^8
- support any linear code (Reed-Solomon, LDPC, random sparse matrix, etc.)
- support more than 2^16 blocks
- support "tail packing", where a block holds data from multiple files
- support deduplication, where the same block appears in multiple files
- replace MD5 hash (It is both slow and less secure.)
- dropped requirement for 4-byte alignment of data

Part of "support any linear code" is to fix the major bug in Parchive 2.0.  Parchive 2.0 did not do Reed-Solomon encoding as it promised.  There was a major mistake in the paper that Parchive 2.0 relied on.  The problem manifested as a bug in Parchive 1.0 and, while Parchive 2.0 reduced its occurrence, it did not fix the problem.  Parchive 2.0 did not use an always invertible matrix; it essentially used a random matrix, which (luckily) is invertible with high probability.  Parchive 3.0 fixes that bug.

The other part of "support any linear code" is supporting codes beside Reed-Solomon.  Reed-Solomon has excellent data protection, but is slow to compute.  LDPC and sparse random matrices will speed things up dramatically, with a slight increase in errors that cannot be recovered from.

Note: The design of Parchive 3.0 focuses on redundancy for a set of files on a disk.  This matches the Parchive 1.0 use case of sending files on Usenet, as well as the growing usage of Parchive to protect against faulty disks.  There were other design ideas, such as redundancy for a stream or to build redundancy into a (user-level) file system.  Both of these are interesting possibilities, if any open source designers need an idea.  Another good idea would be to build a user-level append-only file system using files that match this specification.  (Append-only file systems are important for record keeping in government and banking.)


### The Math of Redundancy

The major feature of Parchive is to support redundant data.  Parchive uses Linear Algebra to generate the redundant data and, after damage, to recover the original input data.  To understand how it works, you need to be familiar with vectors, matrices, etc.

The calculation of redundant data starts with the input data being packaged into a set of vectors.  Those vectors are multiplied by the "code matrix" to generate vectors of redundant data.  Thus, the redundant data vector "r" is equal to the code matrix "C" times the input data vector "i": 

`r = Ci`

Assuming that some data is damaged in transmission or storage, the first step in recovery is identifying the good input data and good redundant data.  Good data is data that arrived intact; bad data was lost or damaged.  We can then permute the elements of each vector to partition them into "good" ones and "bad" ones.  The permuted r and i are now:


```
r = | r_good |
    | r_bad  |

i = | i_good |
    | i_bad  |
```

To keep the equation, we also need to permute the rows and columns of the code matrix to match each vector.  The permuted C and the equation are now:

```
C = | C_good,good C_good,bad |
    | C_bad,good  C_bad,bad  |

| r_good | = r = Ci = | C_good,good C_good,bad || i_good |
| r_bad  |            | C_bad,good  C_bad,bad  || i_bad  |
```

Our goal, of course, is to recover the bad input data.  To do that, we pull out the equation for the good redundant data...

`r_good = C_good,good*i_good + C_good,bad*i_bad`

... and solve for the bad input data:

`i_bad = C_good,bad^-1*(r_good - C_good,good*i_good)`

Here, "^-1" indicates the left inverse of the matrix.  Since the redundant data was made by multiplying the input data by the code matrix, the inverse of a submatrix of the code matrix allows us to recreate the missing input data from the redundant data.  Not every matrix has a left inverse.  When the left inverse does not exist, we cannot recover the input data.  The left inverse never exists when a matrix has more columns than rows, which means we cannot recover if there are more bad input blocks than good redundant blocks.

Unlike in your Linear Algebra class, the elements of the vectors and matrices are not real numbers or complex numbers, but elements of a "Galois field".  Like the computer's integers (a.k.a., the integers modulo 2^N), Galois fields come in various sizes like 8-bits, 16-bits, etc. and support operations called addition, subtraction, multiplication, and division.  Unlike the computer's integers, "division" exactly inverts "multiplication" for every value.  (Computer integers can overflow during multiplication, preventing division from inverting the multiplication.)  That perfect inversion allows the Linear Algebra to work.

Parchive 3.0 improves on Parchive 2.0 by supporting multiple Galois fields and by supporting any code matrix.  This means Parchive 3.0 supports a large set of error correcting codes known as "linear codes".  These include Reed-Solomon and many Low Density Parity Check (LDPC) codes.  This flexibility allows Parchive 3.0 clients to choose between speed and the number of errors that can be recovered.  It also allows Parchive 3.0 to support any new linear code that might be developed.


### Specifics of Computation 

This section goes into the details of how redundant data is computed and how recovery proceeds.  That is, how the mathematical vectors from the previous section are related to actual bytes in a file.

Generating the recovery data starts with choosing a Galois field.  The Galois field is usually chosen by the client based on whatever is fastest for the computer's hardware.  Sometimes larger Galois fields are chosen to enable more redundancy.  For the example in this section, we'll assume the Galois field fits in 2-bytes (16-bits).

Next, the user chooses a block size.  The block size is the smallest unit for recovering data.  It is usually chosen to match the transmission/storage technology or to limit overhead.  The block size must be a multiple of the size of the Galois field.  For our example, it will be 2048 bytes, but in practice it can be much larger, even gigabytes.

Next, the client packs all of the input data into equal-sized blocks.  There are many steps to this.  What follows is a list of the operations, but the specifics of each will be described in detail later.  First, the client breaks the files into variable-length chunks.  (Files can share chunks, which is how Par3 encodes multiple files that contain the same data.)  Second, the chunks are chopped into equal-sized blocks.  If the end of a chunk doesn't completely fill a block, the end can be packed with the ends of other chunks into a single block.  Lastly, any incompletely-filled block is padded with zero bytes.  By the end of these operations, the input data is converted to equal-sized blocks.  For our example, we'll assume the input data takes up 100 blocks, each 2048 bytes long.  Each of those 100 blocks can be seen as holding 1024 Galois field values (each 2-byte in size).  

The next step reorganizes the blocks into vectors.  The 100 blocks containing 1024 Galois field values become 1024 vectors containing 100 Galois field values.  This is done the obvious way: swapping rows for columns and columns for rows.  The values in the i-th block become the i-th element of each vector; the j-th value in each block are used to make the j-th vector.   

Next, the user chooses the numbers of recovery blocks that they want. The number of recovery blocks determines the maximum number of damaged/missing input blocks that we can recover.  Often the number of recovery blocks is 5% or 10% of the number of input blocks. 

Next, the user chooses a code matrix.  The code matrix has a column for each input block and a row for each recovery block.  The elements of the matrix can be anything --- Parchive 3.0 supports any linear code.  Codes vary in speed and the probability of recovering from an error.  Some common choices for the code matrix will be a Cauchy matrix, for recovering any possible damage, or a sparse random matrix, for speed.

Next, for all the input vectors, the client makes a recovery vector by multiplying the input vector with the code matrix.  There is only one code matrix; the code matrix is the same for every pair of vectors.  Since there is one recovery vector for each input vector, there are 1024 recovery vectors.  The length of each recovery vector is equal to how many recovery blocks we want.  

The next step reorganizes the recovery vectors into recovery blocks.  It is basically the inverse of the step that reorganized the input blocks into input vectors.  If we want 5 recovery blocks, the 1024 recovery vectors of length 5 become 5 recovery blocks with 1024 Galois field values.  The i-th element in each vector goes into the i-th recovery block; the j-th vector is used to make the j-th value in each recovery block.  Notice that the recovery blocks are the same size as the input blocks.  Each has 1024 Galois field values and each value takes 2-bytes, so the recovery blocks are each 2048 bytes.

The recovery blocks are written into Par3 file(s) using the "Recovery Data packet" format (specified below).  The input blocks can be stored in their original files or stored in the Par3 file(s) using the "Data packet" format (specified below).  The encoding client also writes filenames, the directory structure and (optionally) file permissions into the Par3 file using the other packet formats.

Once the encoding client has written the Par3 file(s), the user can then store or transmit the Par3 file(s) and, if they choose, the original input files.

After storage or transmission, a (possibly different) user can use a (possibly different) Par3 client to regenerate the original files or, if the original input files were stored/sent, check those files.  The following steps will describe what happens when the original input files were stored/sent.  The complete regeneration of the original input files from the Par3 files is similar.

The decoding client's first step is to check the Par3 files.  The Par3 files contain checksums for the data contained in them.  Any damaged part of a Par3 file is discarded.  Par3 files usually contain duplicated data so that discarding a part of the file does not prevent recovery.  If the Par3 file is incomplete, the decoding client performs the steps that it has data to do, but may be unable to verify or recover the original input set.  

Next, the decoding client checks if the original input files were store/sent correctly.  The Par3 files contains checksums for the contents of every file and a checksum that represents the files' names, entire directory tree, and (optional) file permissions.  The decoding client verifies those checksums and, if the original input files are not present or are damaged, the decoding Par3 client attempts to recover the original files.

To do that, the decoding client searches for all the input blocks.  The Par3 file(s) contain a checksum for every input block and every recovery block.  The decoding client searches the Par3 file(s) and input files for all the input blocks and uses the checksums to determine which are damaged.  If any input block is missing or damaged, recovery of the input blocks is attempted. 

The first step to recovering the input blocks has already been done: determine which input blocks are good (present and unchanged) or bad (missing or damaged).  This information is converted into which elements of the input vectors need to be recovered.  (This was "i_bad" in a previous section.)

Next, the decoding client uses the recovery block checksums in the Par3 file to identify good recovery blocks.  It then converts those blocks into which elements of the recovery vectors can be used to recover the missing input data.  (This was "r_good" in the previous section.)

Then, the client performs the math (described above) which uses the good elements of each recovery vector to recover the bad elements of its associated input vector.  The math requires inverting a submatrix of the code matrix.  There are many ways that the client can invert a matrix (for example: Gaussian elimination, Fast Fourier Transform (FFT), and the incremental approach used by LDPC).  Clients may consider multiple strategies.  If the matrix's left inverse does not exist, recovery fails.  If the left inverse exists, the decoding client uses it to calculate the missing elements of the input vectors.

After recovering the missing elements of each input vector, the data is reorganized to regenerate the missing input blocks.  Those blocks and any pre-existing input blocks are written to the appropriate place in the appropriate files.

Once the file contents have been recovered, the decoding client uses the other data in the Par3 file to rename, move, or (optionally) set the permissions on the files and directories to match the original input set.  

Before ending, the decoding client verifies the checksums of the input files, directories and (optional) permissions.  This final verification ensures that the decoding client did not make a mistake during the complicated process of recovering the input blocks and complete input set.

Having described the math behind recovery and how the encoding and decoding clients manipulate the bytes to make the math work, the rest of the specification goes into the details of the file format.


## File Layout

### Conventions

There are a number of conventions used in this specification.

The abbreviation "kB" refers to 2^10 = 1,024 bytes.  (Disk sales people have sometimes used "kilobyte" or "kB" to mean 10^3 = 1,000 bytes.  The result was the unambiguous but little used "kibibyte" or "KiB".)  

All integers in this version of the spec are integers of 1, 2, 4, 8, or 16 bytes in length.

All integers are little endian. (This is the default on x86 and x86-64 CPUs, but not other architectures.)  Signed integers are in 2's complement notation.  (This is the default on every major architecture.)  

Strings are not NUL-terminated.  This is to prevent hackers from using stack-overflow attacks.  If an N-byte field contains an array, a null-terminated string can be created by copying the N-byte field into a character array of length N+1 and then the setting the N+1 character to '\0'.

The lengths of arrays and strings are often implicit.  For example, if a region is known to be 32 bytes and that region contains an 8-byte integer and a string, then the string is known to take up 24 bytes. 

All strings are UTF-8.  *WARNING: Writers of OSX/MacOS clients must take special care with UTF-8 filenames!  Unicode has multiple ways to encode the same string.  An e with an accent mark can be encoded as a single character (U+00e9) or two characters, one for the e (U+0065) and one for the accent mark (U+0301).  Par3 does not require a particular encoding.  Forcing a particular encoding is called "normalization" in the Unicode vocabulary.  Most file systems do not normalize filenames and just treat the UTF-8 as a sequence of bytes.  Par3 follows their practice.  However, HFS+ was Apple's default file system from 1998 to 2017 and it normalizes every filename.  Thus, if a Parchive 3.0 client writes a file with a UTF-8 filename, the HFS+ file system may change the filename.  Clients for OSX/MacOS should be aware of this possibility.  Apple's current default file system, APFS, does not do normalization.*

The lengths of input files and locations in input files can be 8-byte integers or larger.  There is no limit on the length of a Par3 file.  (Hard drive size doubles every 1.5 years and is expected to exceed 8-byte integers before 2040.)  Clients MAY choose not to support files that are larger than 2^64.  Clients that do not support large files must inform the user if they encounter a Par3 file containing too large a file.

The block size and matrix indices are 8-bytes integers.  In order to protect files with more than 2^64 bytes, users must choose larger block sizes.  

Par3 uses two hash functions.  The "rolling hash" is CRC-64-ISO.  The rolling hash is used to identify input blocks that are not in their expected location.  This hash is only 64-bits long and may not uniquely identify a block.  

The "fingerprint hash" is the lower 16-bytes of a Blake3 hash.  It is used to uniquely identify blocks.  If two blocks have the same fingerprint hash, they are assumed to have identical contents.  

TODO: Make sure "lower 16-bytes bytes" above is specific.

Padding between packets, if done at all, is specified to be zero bytes.

The order of items in all arrays is specified.

When discussing vectors and matrices, this document uses zero-indexing.  That is, the elements in a vector are at locations 0 through N-1.  (One-indexing, the usual convention in mathematics, has them at locations 1 through N.)


### Packets

A Par3 file is made of packets: self-contained parts with their own checksum. This design prevents damage to one part of the file from making the whole file unusable.  

Packets have a type and each type of packet serves a different purpose.  One type describes the code matrix.  Another contains input blocks.  Yet another contains a recovery block.  There are many other types.

A Par3 file is only required to contain 1 specific packet: the packet that identifies the client that created the file.  This way, if clients are creating files that don't match the specification in some way, they can be tracked down.

All packets contain an InputSetID.  It uniquely identifies the set of input files and directories.  The packets to recover a particular set of input files can be stored in multiple Par3 files.  In that case, the packets can be identified because they will all share the same InputSetID.  The packets to recover different sets of input files can be stored inside the same Par3 file.  In that case, the packets can be told apart by their different InputSetIDs.  To handle incremental backups, an InputSetID can have a "parent" InputSetID.  With a few exceptions, the packets of the parent (and any of its ancestors), are considered packets of the child InputSetID.  

Packets can be duplicated.  In fact, duplicating packets is recommended for vital packets, such as the one containing the file checksums.  This is because Parchive's recovery mechanism only protects the contents of files, not the files' metadata nor the code matrix.  Duplicating packets with the metadata and code matrix is one way to protect it against loss.  (Another way to protect it is "Par inside Par", described below.)

Packets can appear in any order.  Because packets can be lost or mishandled, it is impossible to guarantee the order that packets arrive at the decoding client.  Nonetheless, there is a recommended order for packets, which, if most packets arrive correctly, allows the decoding clients to recover the files in a single pass.  



#### Packet Header

A Par3 file consists of a sequence of "packets".  A packet has a fixed-sized header and a variable length body.  The fields of the header are:

*Table: Packet Header*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  8 | byte[8]  |  Magic sequence. Used to quickly identify location of packets. Value = {'P', 'A', 'R', '3', '\0', 'P', 'K', 'T'} (ASCII) |
| 16 | fingerprint hash | 16-bytes of Blake3 hash of packet. Used as a checksum for the packet. Calculation starts after this field and ends at last byte of body. Does not include the magic sequence or this field. |
|  8 | unsigned int | Length of the entire packet.  (Note: Includes length of header.) |
|  8 | InputSetID | All packets for the same input set have the same InputSetID. (See below for how it is calculated.) |
|  8 | byte[8] |  Packet type. Can be any value. All beginning "PAR " (ASCII) are reserved for specification-defined packets.  Application-specific packets must have an application-specific 4-byte prefix. |
|  ? | ? |Body of Packet. |

The magic sequence is a constant value that is the same in every packet.  It is used when searching for packets in a file.  (The magic sequence begins with "PAR3\0" so that if someone looks at the contents of a Par3 file in a text editor, it starts with "PAR3".)

The checksum is used to determine if any part of the packet has been changed during storage/transmission.  The checksum does not cover the magic sequence nor the checksum field itself; it covers everything after (including all of the body).  If the checksum of the data read/received does not match this field's value, the packet is ignored.  

The length of the entire packet is measured in bytes.  It includes the length of header.  (Note: In Par 3, packets are not required to be 4-byte aligned and packet lengths are not required to be a multiple of 4-bytes.  If a client wished to align packets, zeroed bytes can be inserted between packets.)

The InputSetID is used to identify packets that should be processed together, even if those packets were written to separate Par3 files.  The InputSetID is a globally unique random number.  See the Start packet description below for an explanation of how it is generated.

The packet-type field is used to distinguish the different types of packets.  Clients MUST be able to process the "core" packet types listed below.  Client MAY process the optional packets or create their own application-specific packets.   The packet type is not guaranteed to be a string or even ASCII valued.  (Note: The types of required packets are ASCII strings so that a developer can run "strings file.par3 | grep PAR" and see what packets are in a file.)  If the client does not recognize the packet type, the packet is ignored.  

The body contains data that is particular to the packet type.  There are various types of packets. The "core" set of packets --- the set of packets that all clients must recognize and process --- are listed next. For each, the value for the "type" field will be listed along with the contents of the body of the packet. 


#### Creator packet

This packet is used to identify the client that created the Par3 file.  It is required to be in every Par3 file.

This packet is used for debugging.  If a decoding client is unable to recover the input set due to a badly created file, the contents of the creator packet MUST be shown to the user.  (An automated system MUST write the information to a log file.)  The goal of this is that any client incompatibilities can be found and resolved quickly.

The Creator packet has a type value of "PAR CRE\0" (ASCII). The packet's body contains the following:

*Table: Creator Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| ? | UTF-8 string | UTF-8 text identifying the client, options, and contact information.  Reminder: This is not a null terminated string. |

The text in the Creator packet MUST identify the client that created the file.  It MUST include the version number of the client.

It is RECOMMENDED that the text also include the parameters used to generate the Par3 file.  For example, a command-line tool could include all the command-line options.  A GUI client might include a snippet of the program's log file.

It is RECOMMENDED the text include a way to contact the author of the tool.  For example, an email address or the URL of a web page for submitting new issues.  


#### Comment packet

The Comment packet contains a comment in UTF-8.  This string SHOULD be shown to the user.  (An automated system SHOULD write the information to a log file.)  If multiple copies of the same Comment packet are found, only one should be shown.

The Comment packet has a type value of "PAR COM\0" (ASCII). The packet's body contains the following

*Table: Comment Packet Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| ? | UTF-8 string | The comment. Note: This is not a null terminated string! |



#### Start packet

This packet specifies the Galois field and block size.  It can also hold a "parent's" InputSetID, if this Par3 file wants to reuse data from an existing Par3 file. 

The Start packet has a type value of "PAR STA\0" (ASCII). The packet's body contains the following:

*Table: Start Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  8 | Random | A globally unique random number |
|  8 | InputSetID | The "parent" InputSetID, or zeros if none. |
| 16 | fingerprint hash | The checksum of the parent's Root packet, or zeros if none. |
|  8 | unsigned int | Block size in bytes |
|  1 | unsigned int | The size of the Galois field in bytes. |
|  ? | ?-byte GF | The generator of the Galois field without its leading 1. |

The first field is a globally unique number.  (See below for how to generate a globally unique number.)  The globally unique number ensures the InputSetID (explained below) is unique.  

The second field is used for an "incremental backup".  If the user wants this Par3 file to reuse the data in Par3 files for another input set, then this field is set to the InputSetID in the "parent's" Par3 packets.  Otherwise, the field is all zeros.  If the field is set, all the packets with the parent's InputSetID (and any of its ancestors) are considered packets with this packet's InputSetID with the following conditions.  The parent and ancestors' Root packets are not used to determine the input set.  And, the parent and ancestors' Start packets must all have the same block-size and Galois field as this packet.  

The second field is also used for an "incremental backup".  It holds the checksum of the parent's Root packet, or, if there is none, all zeroes.  The checksum of the parent's Root packet guarantees that the parent's input set was completely specified before this input set's was started.  

The block size determines the length of input blocks and recovery blocks.  The block size must be a multiple of the Galois field size.  If the parent's InputSetID is present, the block size must be the same as the parent's. 

The Galois field size says how many bytes are used to hold a Galois field element.  If the parent's InputSetID is present, the Galois field (both size and generator) must be the same as in the parent. 

The Galois field's generator is written in little-endian format without its leading 1.  Thus, if the Galois field had a size of 2-bytes and a generator of 0x1100B, the entry's first two bytes would hold the value 0x100B in little-endian format.  Notice that the packet does not store the leading 1 that is present in the mathematical notation of the generator.  More information is available in the section on Galois fields below.



There is only one Start packet for an InputSetID.  There can be multiple identical copies of this packet in the file.  (This is true for all packets.)

Start packets are used to generate the InputSetID, which is included in the header of every packet.  The InputSetID is the first 8 bytes of the Blake3 hash of the body of the Start packet.  To be clear, the hash for the InputSetID does not include the header of the packet.  (Including the header is actually impossible, since the hash would have to contain a hash of itself.)  

TODO: Make sure "first 8 bytes" above is specific.

Note: There are many ways to generate a globally unique random number.  One way is to use the fingerprint hash of the triple consisting of: a machine identifier, a process identifier, and a high-resolution timestamp.  (Be careful that the machine identifier is actually unique!  Many computers share the same IP Address in one of the private address ranges.)  Another method for generating a globally unique number is, if the input set's data is known ahead of time, is to use a fingerprint hash of the parent's InputSetID, block size, Galois field parameters, and all the files' contents.  A third method is to use an internet service, like random.org.  Be careful with services, since if it goes down or offline (like the imaginative "LavaRand"), the client's users will be unable to generate new Par3 files.


#### Data Packet

This packet contains one block of data from the input files.

The Data packet has a type value of "PAR DAT\0" (ASCII). The packet's body contains the following:

*Table: Data Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  8 | unsigned int | The index of the input block |
|  ? | byte[] | The data itself. |

The input block's index is used with the File packets (described below) to say where this data occurs in files.  Input block indices are used consecutively, so an input set will generally use all block indices from 0 up to a particular value.

Data packets contain one entire block's worth of data.  The data's length is implicit.  (The packet's entire length is written in the packet header.)  If the data's length is less than the block size, the rest of the block is filled with zero bytes.  The data cannot be longer than the block size.


#### External Data Packet

This packet contains checksums for input blocks that are not stored inside a Data packet.  The most common case is when input files are kept around and have the data inside them.  Should those files be partially damaged, the good data stored in them can be used for recovery.  The checksums in this packet are used to find and verify that good data.

The External Data packet has a type value of "PAR EXT\0" (ASCII). The packet's body contains the following:

*Table: External Data Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8 | unsigned int | Index of the first input block |
| 24*? | {rolling hash, 16-byte fingerprint hash} | A rolling checksum and fingerprint for each input block |

The index for the first input block for which there is a checksum.  

The tuples contain a rolling hash (CRC-64-ISO) and fingerprint hash (16-byte Blake3 hash) for each block in a sequence of input blocks.  Thus, the first pair of checksums is for a block with the index written in the packet.  The second pair of checksums is for the block index plus 1.  Etc.

Note: The rolling hash is used to locate a block when data might have shifted location.  The fingerprint hash is used to confirm that the block is the correct block (because the rolling hash is less trustworthy).  There is more about the rolling hash in the section "Rolling Hash" below.



#### Matrix Packets

A matrix packet determines a portion of the code matrix and specifies how one or more recovery blocks were computed.  There are 3 different types of matrix packets.  More than one type can be used at the same time.  For example, a sparse matrix packet could be used to generate most recovery data and a Cauchy matrix packet to generate a few blocks of recovery data.  (This dual approach balances speed and recovery of errors.)

Parchive 3.0 has 3 different types of matrix packets: Cauchy, Sparse Random, and Explicit.

##### Cauchy Matrix Packet

This packet describes a Cauchy matrix.  It is used for all or part of the code matrix.  A single Cauchy Matrix packet determines multiple rows of the code matrix and can be used with multiple Recovery Data packets.

The Cauchy matrix creates the best possible recovery data.  With the Cauchy matrix, any submatrix that can have a left inverse does have a left inverse.  (That is, any submatrix which doesn't have more columns than rows, has a left inverse.)  Using just one Cauchy matrix creates a Reed-Solomon code.  

The Cauchy matrix packet has a type value of "PAR CAU\0" (ASCII). The packet's body contains the following:

*Table: Cauchy Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8 | unsigned int | Index of first input block |
| 8 | unsigned int | Index of last input block plus 1 |
| 8 | unsigned int | hint for number of recovery blocks |

The recovery data is computed for a range of input blocks.  The range is denoted using a "half-open interval".  So, to compute recovery blocks for input blocks 3, 4, and 5, the range is denoted by 3 and 6.  If the encoding client wants to compute recovery data for every input block, they use the values 0 and 0.  (Because the maximum unsigned integer plus 1 rolls over to 0.)  The matrix's elements for all input blocks outside the range is 0.

The hint to the number of recovery blocks is used in single-pass situations to allocate buffers.  If the number of rows is unknown, the hint is set to zero.  

For the non-zero elements of the matrix, the element for input block I and recovery block R depends on I and R.  (Note: This specification uses zero-index vectors, so I and R start at 0.)   Specifically, it is the multiplicative inverse of x_I-y_R, where x_I is the Galois field element with the same bit pattern as binary integer I+1 and y_R is the Galois field element associated with the binary integer MAX-R, where MAX is the maximum binary unsigned integer value with the same size as the Galois field.  (Note: In binary, MAX contains all ones.)  To be clear, the multiplicative inverse and subtraction x_I-y_R are done using Galois field arithmetic.  The I+1 addition and MAX-R subtraction is done using native integer arithmetic.

Mathematically, that is: inv( (I+1) ^ (~0-R) ) = inv( (-2-I) ^ R ) where the GF element fits in an twos-compliment integer, "inv()" is the Galois field's multiplicative inverse, "~" denotes bitwise NOT and "^" denotes bitwise XOR.


##### Sparse Random Matrix Packet

This packet describes a sparse random matrix.  With a sparse matrix, it is faster to calculate recovery blocks, but the user has to accept a slightly higher chance of not recovering from extreme cases.

If it feels wrong to increase the probability of failure, recall that for any matrix, it must fail if insufficient input and recovery blocks arrive.  Using a sparse matrix, rather than a Cauchy, can run many times faster.  Users that can store/send a handful of additional recovery blocks can get much faster performance with a minuscule increase in failure to recover.  See "Sparse Matrices" below for details about how to use this packet and the probability of failure.

The Sparse Random Matrix packet has a type value of "PAR SPA\0" (ASCII). The packet's body contains the following:

*Table: Sparse Random Matrix Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8 | unsigned int | Index of first input block |
| 8 | unsigned int | Index of last input block plus 1 |
| 8 | unsigned int | maximum number of recovery blocks |
| 8 | unsigned int | number of non-zero elements per input block |
| 8 | unsigned int | random number generator seed |

The recovery data is computed for a range of input blocks.  (See Cauchy Matrix packet.)  The matrix's elements for all input blocks outside the range is 0.

Otherwise, each of the input block's non-zero elements are generated and then shuffled into position.  The following paragraphs describe the details.

1. Allocate a matrix with R rows and C columns, where R is the number of input blocks and C is the number of recovery blocks

2. Go row-by-row from low index to high, generating each row as follows:

  - Fill the row with C-X zeroes and X random Galois field values.  The zeroes go in the low indexes; the random values in the higher ones.  The method for generating a random Galois field values is below.  The order of requests to the random number generator is important: the values should be assigned from the lowest column index to the greatest.  

  - Shuffle the row.  Once shuffled, the random non-zero values will then be evenly distributed.  The shuffle algorithm is the "inside-out" version of the "Fisher-Yates shuffle".  Skip the shuffle for the first C-X elements, because they are all zeroes and shuffling them does nothing.  The first non-zero value is at index C-X and is swapped with a random location in the range 0 to C-X.  The next non-zero value is at index C-X+1 and is swapped with a random location in the range 0 to C-X+1.  Continue until all the non-zero elements are shuffled.  The random location values are generated by treating a random 64-bit value as an unsigned integer and using modulus (the % operator in C, C++, Java, python, etc.).  

The random number generator is a "Permuted congruential generator" that generates 64-bit values.  Specifically, it is "PCG-XSL-RR".  The generator has a 128-bit state.  The seed goes into the lower bits of the state.  The upper bits of the state are zeroed.

Generating a B-byte random non-zero Galois field value is done as follows:  If B is greater than 8-bytes, the 64-bit values from the random number generator are put into the Galois field value from lowest byte-index to highest.  For the last (B modulo 8) bytes, the lowest bits of the random 64-bit value are used.  This is the same as if the random value was taken modulo 2^(8*B).  Lastly, if the random value generated by this process was zero, the value is ignored and a completely new value is generated in its place.  

The final result is a matrix where every row has X randomly-located non-zero random values.  This will mean data from from each input block will be incorporated into X different recovery blocks. 

Note: When using random values and the modulus operator ('%' in C/C++/Java/python), be careful that the random value is treated as an unsigned value, and not a signed one.  Some modulo operators, like Java's, can return a negative value on signed input.  (Java's operator is actually calculating "remainder" and not "modulus".)


##### Explicit Matrix Packet

This packet describes a matrix that computes a single recovery block.  The values of the elements are explicitly contained in the packet, and not computed like the other matrix packets.  This packet is intended to be used for LDPC, such as Tornado Codes.

The Explicit Matrix rows packet has a type value of "PAR EXP\0" (ASCII). The packet's body contains the following:

*Table: Explicit Matrix Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| ?*(8+?) | {8-byte unsigned int, GF value} | input block index, Galois field value |

The matrix contains values for a single row of the code matrix.  There will be only one recovery block associated with this matrix.  For each input block that is used to calculate the recovery block, there is a pair of the index of the input block and its Galois field factor.  The pairs are in sorted order, with input block indices increasing from lowest to highest.  Any block indices not present have a factor of zero.



#### Recovery Data Packet

This packet contains a recovery block.

The Recovery Data packet has a type value of "PAR REC\0" (ASCII). The packet's body contains the following:

*Table: Recovery Data Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 16 | fingerprint hash | The checksum from the Root packet |
| 16 | fingerprint hash | The checksum from the Matrix packet |
| 8 | unsigned int | The index of the recovery block |
| ? | data | The recovery block data |

The Root packet checksum is used to determine the input blocks that were used to calculate the recovery data in this packet.  The recovery data is only calculated using input blocks up to the maximum index recorded in the Root packet.  

The Matrix packet checksum and recovery block index together indicate the row of the code matrix used to calculate the recovery data in this packet.  There can be multiple Matrix packets and each has their own range of recovery block indices.  For example, a Par3 file can contain a Sparse Matrix packet with recovery block indices 0 through 100 while also containing a Cauchy Matrix packet with its recovery block indices going from 0 to 3.  Explicit Matrix packets can have only one recovery block and its index is specified to be 0.

The data field holds the recovery block's data.  The data's length is implicit.  (The packet's entire length is written in the packet header.)  If the data's length is less than the block size, the rest of the block is filled with zero bytes.  The data cannot be longer than the block size.

Note: When using data from a Recovery Data packet, it is important to check the Root packet's "lowest unused input block index".  This is because when recovering from an "incremental backup", we don't want to try to use the parent's Recovery Data packets to recover the child's new data.  Both parent and child can have Recovery Data packets using the same matrix packet and even reuse the recovery block indexes.  We can find the upper limit of input blocks that can be recovered using the parent's recovery data by finding the Root packet that matches the checksum and looking at the Root packet's "lowest unused input block index".  


#### Recovery External Data Packet

This packet contains checksums of recovery blocks that are not stored inside a Recovery Data packet.  

This packet is added for completeness.  In case some client wants to store recovery data outside a Par 3.0 packet. 

The External Recovery Data packet has a type value of "PAR ERD\0" (ASCII). The packet's body contains the following:

*Table: External Recovery Data Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 16 | fingerprint hash | The checksum from the Root packet |
| 16 | fingerprint hash | The checksum from the Matrix packet |
| 8 | unsigned int | Index of the first recovery block |
| 24*? | {rolling hash, 16-byte fingerprint hash} | A rolling checksum and fingerprint for each recovery block |

The Root packet checksum acts the same as with the Recovery Data packet.

The Matrix packet checksum acts the same as with the Recovery Data packet.  It is used together with the recovery block indices (below) to determine the row of the code matrix used to generate the recovery data. 

The index is the recovery block index for the first block for which there is a pair of hashes.

The tuples contain a rolling hash (CRC-64-ISO) and fingerprint hash (16-byte Blake3 hash) for each block in a sequence of recovery blocks.  Thus, the first pair of checksums is for a block with the index written in the packet.  The second pair of checksums is for the recovery block index plus 1.  Etc.

Note: The rolling hash is used to locate a block when recovery data might have shifted location.  The fingerprint hash is used to confirm that the recovery block is the correct block (because the rolling hash is less trustworthy).  There is more about the rolling hash in the section "Rolling Hash" below.



#### File Packet

This represents a file in the input set.  It holds a filename, optional file permissions, and the mapping of the file's data to input blocks.

Parchive 3.0's default behavior is to ignore all metadata except for the filename (and directory location, which is stored elsewhere).  Since each file system stores a different set of metadata, there are optional packets that can store the metadata for some file systems.  

The File packet has a type value of "PAR FIL\0" (ASCII). The packet's body contains the following:

*Table: File Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  2 | unsigned int | length of filename in bytes |
|  ? | UTF-8 string | filename |
|  8 | rolling hash | hash of the first 16kB of the file |
| 16 | fingerprint hash | hash of the protected data in the file |
|  1 | unsigned int | number of options (a.k.a. permissions) |
| 16*? | fingerprint hashes | checksums of packets for options |
| ?*?  | chunk descriptions |  see below. |

The first field holds the length of the filename in bytes.  (FYI: 255 bytes is the limit on NTFS, EXT4, and exFAT.  ReiserFS supports 255 characters, in up to 4kB of storage.  Yutaka-Sawada claimed Windows Explorer allowed him to name files with 239 Japanese Unicode codepoints, each of 3-bytes in size, which is 717 bytes.)

The filename is a UTF-8 string.  It is not NUL-terminated.

The third field holds a rolling hash of the first 16kB of the file.  (Note: 16kB is 16*1024 bytes.)  This value is used to quickly identify files that have been moved or renamed.  If the file is shorter than 16kB, the field holds the rolling hash of the entire file.  If any of the first 16kB bytes of the file are unknown, this field is all zeroes.  This hash is only a hint --- it is not guaranteed to match an input file because any bytes at the front of a file might have been damaged (deleted/replaced/added).  The value is not guaranteed to be unique, since many files can start with the same first 16kB bytes (and because the rolling hash is not guaranteed to be unique).  This rolling hash may include data that is not protected (see below).

The fourth field holds a fingerprint hash of the protected data in the file.  For most files, this will be all the data.  If it is all the data, the hash will be the same value as computed by external programs, such as "b3sum".  Because of features like "Par inside", some of the file's data may not be protected.  (See "chunk descriptions" below to tell which parts are not protected.)  In those cases, the hash is still calculated, with the unprotected sections assumed to be zero bytes.  

The next two fields hold the number of options and the checksums of the packets holding those options.  For a File packet, the options are FAT Permissions packets and UNIX Permissions packets.  There can be at most one of each type.  Future versions of Parchive may include more option packets (for example: NTFS permissions, etc.).  Clients can add their own custom packet types that can appear as File packet options.  If the decoding client cannot find a packet with that checksum or does not recognize an option packet, the client may still recover the file.  Clients SHOULD warn the user if a packet with a particular checksum could not be found or if an option packet's type is not recognized.

The last field is a sequence of chunk descriptions.  The input file is divided into a sequence of variable-length chunks and the chunk descriptions explain how to map each chunk to input blocks.  The chunks cover every byte of the file and do not overlap.  The chunk descriptions are in the order that the chunks appear in the file.  Thus, the starting location of a chuck can be determined by summing the lengths of the preceding chunks.  The length of the file can be determined by summing the lengths of all chunks.

Chunks are either protected or not protected.  A protected chunk has input blocks associated with it and contributes to the file's checksum.  Almost all chunks will be protected.  An unprotected chunk is not associated with any input blocks and, when computing the file's checksum, are assumed to be filled with zero bytes.  Unprotected chunks will almost always be a result of using the "Par inside" feature.

*Table: Protected Chunk Description Layout*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  8 | unsigned int | length of protected chunk |
| ?8 | unsigned int | OPTIONAL [length is least 1 block size] index of first input block holding chunk |
| ?1 to 39 | raw data | OPTIONAL [tail > 0 bytes and tail < 40 bytes] tail's contents |
| ?8  |rolling hash | OPTIONAL [tail >= 40 bytes] hash of first 40 bytes of tail |
| ?16 | fingerprint hash | OPTIONAL [tail >= 40 bytes]  hash of all of tail |
| ?8  | unsigned int | OPTIONAL [tail >= 40 bytes] index of block holding tail |
| ?8  | unsigned int | OPTIONAL [tail >= 40 bytes] offset of tail inside block |

For a protected part of a file, a chunk description starts with the length of the chunk.  If the chunk's length is at least 1 block-size, the next field holds the index of the first input block holding the chunk's data.  That first input block holds the first block-sized piece of the chunk's data.  Subsequent block-sized pieces of the chunk are assigned to increasing input block indices.  If the chunk's total size is not a multiple of block-size, the chunk with end with a "tail" that is less than a block-size long.  The remaining fields cover the tail.

If the protected chunk has a tail and the the tail is less than 40-bytes long, the tail's raw data is inserted into the chunk description.  (This is known as "inline data".)  If there is a tail and the tail is longer than 40 bytes, the final 4 fields exist to cover it.  The fields are: a rolling hash of the first 40 bytes of the tail, a fingerprint hash of the entire tail, the index of the input block holding the tail's data, and the offset of the start of the tail inside that block.  Many tails can be packed into a single input block.  Each tail must lie completely inside the single input block holding it and not cross a block boundary.  


*Table: Unprotected Chunk Description Layout*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
|  8 | unsigned int | zeros |
|  8 | unsigned int | length of chunk |

If the chunk is unprotected, the chunk description starts with an 8-byte unsigned int that is set to zero.  This is distinguishable from the protected chunk description, which starts with the length of the chunk and that value has to be greater than zero.

The second field in the chunk description for an unprotected chunk is the length of the chunk.

Chunk descriptions will be easier to understand with a few examples.  Assume we have a block size of 2,000 and a 10,000 byte file following the pattern "abcdefghij", where each letter represents 1,000 bytes of data.  So "a" actually means 1,000 copies of the letter 'a'.  That file would have the following chunk description.  
```
  {length=10000, firstblockindex=0}
```
The blocks would be: 0:"ab", 1:"cd", 2:"ef", 3:"gh", 4:"ij"

The second example is a file that has a "tail".  An 11,000-byte file following the pattern "abcdefghijk" might have the following chunk description.  (Fingerprint and rolling hashes have been dropped for clarity.)
```
  {length=11000, firstblockindex=0, tailblockindex=5, tailoffset=0}
```
The blocks would be: 0:"ab", 1:"cd", 2:"ef", 3:"gh", 4:"ij", 5:"k\0"

The third example is a file that uses multiple chunks.  Assume there are two versions of a file.  The old version of the file is the file from the previous example.  The new version of the file is 15,000-bytes and follows the pattern "abcde0123fghijk", because "0123" has been inserted into the middle of the file.  The new file could be be encoded as 3 chunks.  The first and third chunks reuse the data from the old version of the file and the middle chunk contains the inserted "0123":
```
  {length=5000, firstblockindex=0, tailblockindex=2, tailoffset=0}
  {length=5000, firstblockindex=6, tailblockindex=2, tailoffset=1000}
  {length=5000, firstblockindex=3, tailblockindex=5, tailoffset=0}
```
The blocks would be: 0:"ab", 1:"cd", 2:"ef", 3:"gh", 4:"ij", 5: "k\0", 6: "01", 7: "23".

The fourth example has tail packing and a small file.  A 3,000-byte file following the pattern "abc" and a 1,000-byte file following the pattern "z" might have the chunk descriptions:
```
  {length=3000, firstblockindex=0, tailblockindex=1, tailoffset=0}
```
and
```
  {length=1000, tailblockindex=1, tailoffset=1000}
```
The blocks would be: 0:"ab", 1:"cz"

A fifth example has a 3,000-byte file following the pattern "abc" and a super tiny 10-byte file whole complete contents are "qrstuvwxyz".  The chunk descriptions would be:
```
  {length=3000, firstblockindex=0, tailblockindex=1, tailoffset=0}
```
and
```
  {length=10, taildata="qrstuvwxyz"}
```
The blocks would be: 0:"ab", 1:"c\0"

A sixth example has a file with an unprotected section in the middle.  The 10,000-byte file follows the pattern "abcdefghij" where the middle "cdefgh" is not protected.  This file might have the following chunk description:
```
  {length=2000, firstblockindex=0}
  {length=0, unprotectedlength=6000} 
  {length=2000, firstblockindex=1}
```
The blocks would be: 0:"ab", 1:"ij".  When calculating the fingerprint hash for the file's contents, the unprotected section "cdefgh" would be replaced by zero bytes.

Note: The filename is a filename, not a path.  

Note: See the security section of this document about checking filenames to avoid security breaches.  The security section also has suggestions on selecting filenames that will be portable across file systems.

Note: When assigning the indexes of input blocks used to hold data, clients should generally assign them in increasing order, starting at 0.  The unused higher values are reserved for "incremental backups" that will use this input set as a parent.

Note: Simple clients will probably write Par3 files where each input file consist of a single chunk.  More complex clients may use rolling hashes or "content-defined chunking" or version control data to identify files that share content.  In those cases, the same chunk description may appear in multiple File packets or, even, appear multiple times inside the same File packet.  Although clients writing the file have the choice to support multiple chunks, clients reading the file do not.  All clients MUST be able to decoded File packets with multiple chunk descriptions and perform recovery.  For more information on chunks, see the section "Chunking and Deduplication".

Note: Simple clients can put each "tail" that is longer than 40-bytes into its own input block with a zero offset.  More complex clients may pack multiple "tails" into the same input block.  Nonetheless, all clients MUST be able to decode File packets where multiple tails are packed into the same input block and perform recovery.

Note: Chunk descriptions can reuse input blocks without being identical.  Tails of files can overlap inside the same input block.  Neither of these cases is expected to be common, but they are allowed by the current version of the specification.

Note: Rolling hashes with a block-size window can be used to identify potential data blocks.  Those data blocks can be confirmed using their fingerprint hashes.  Once that has been done, rolling hashes with a 40-byte window can be used to identify that start of tails.  Those tails can be confirmed using their fingerprint hashes.  

Design Note: Most file systems store each file's name inside the directory that contains it.  That can make the directory structure very large.  In Par3, the file's name is included inside the File packet, instead of the Directory packet, to make packets more equally sized.  


#### Directory Packet

This packet represents a sub-directory holding files from the input set.  (The top-level directory is represented by the Root packet.)

Parchive 3.0's default behavior is to ignore all metadata except for the directory's name (and location in parent directories).   Since each file system stores a different set of metadata, there are optional packets that can store the metadata for some file systems.  

The Directory packet has a type value of "PAR DIR\0" (ASCII). The packet's body contains the following:

*Table: Directory Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 2    | unsigned int | length of string in bytes |
| ?    | UTF-8 string | name of directory |
| 4    | unsigned int | number of options (a.k.a. permissions and links) |
| 16*? | fingerprint hash | checksums of packets for options |
| ?*16 | fingerprint hash | checksums of File and Directory packets |

The first byte is the length of the directory's name in bytes.  

The directory's name is a UTF-8 string.  It is not NUL-terminated. 

The next two fields hold the number of options and the checksums of the packets holding those options.  Notice that the number of options is a 4-byte unsigned integer, while it is only 1-byte for the File packet.  The checksums are in numerical order.  For a Directory packet, the options include Link packets, FAT Permissions packets and UNIX Permissions packets.  The permissions apply to the directory itself, so there can be at most one of each type.  There can be any number of Link packets, representing hard or symbolic links contained in the directory.  Future versions of Parchive may include more option packets (for example: NTFS options, special file types, etc.).  Clients can add their own custom packet types that can appear as Directory packet options.  If the decoding client cannot find a packet with that checksum or does not recognize an option packet, the client may still recover the directory and its contents.  Clients SHOULD warn the user if a packet with a particular checksum could not be found or if an option packet's type is not recognized.

The final field is a sequence of packet checksums.  For each file and subdirectory contained in the directory, the checksum of the associated File packet or Directory packet is present here.  The checksums are in numerical order.

It is not allowed for the Directory packet to contain Files or Directories or Links with duplicate names.  Each name must be unique.

Note: The Directory packet and all the File and Directory packets reachable by following checksums represent a tree.  Every supported file system supports a directory tree.  Some file systems, like EXT4 and NTFS, support a directed acyclic graph or "DAG", while others, like FAT and exFAT, do not.   It is valid for the checksum of a File or Directory packet to appear inside multiple Directory packets.  When that occurs, it represents a complete copy of the file or subdirectory.  It is not a hard link.  A common occurrence of this would be 2 different empty directories with the same name.  See the Link packet to see how DAGs are supported by hard links.

Note: Parchive 3.0 supports empty directories. 



#### Root Packet

This packet identifies the top directory in the directory tree holding the input set.  

The Root packet has a type value of "PAR ROO\0" (ASCII). The packet's body contains the following:

*Table: Root Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8 | unsigned int | Lowest unused index for input blocks. |
| 1 | unsigned int |  attributes |
| 4 | unsigned int | number of options (a.k.a. links) |
| 16*? | fingerprint hash | checksums of packets for options |
| ?*16 | fingerprint hash | checksums of File and Directory packets |

The first field holds the lowest unused index for input blocks.  If a client generates an "incremental backup" with this packet's input set as the parent, the client can start assigning new input blocks at this index.

The attributes is a bit field.  At the moment, only the least significant bit is used.  If it is 0, the directory is a relative path.  If it is 1, the directory is an absolute path.   All bits besides the least significant bit must be set to zero.

The next two fields hold the number of options and the checksums of the packets holding those options.  Notice that the number of options is a 4-byte unsigned integer, while it was 1-byte for the File packet.  The checksums are in numerical order.  For a Root packet, the options are Link packets.  There can be any number of Link packets, representing hard or symbolic links contained in the root directory.  Future versions of Parchive may include more option packets (for example: special file types, etc.).  Clients can add their own custom packet types that might appear as Root packet options.  If the decoding client cannot find a packet with that checksum or does not recognize an option packet, the client may still recover the directory's contents.  Clients SHOULD warn the user if a packet with a particular checksum could not be found or if an option packet's type is not recognized.

For each file and subdirectory contained in the top-level directory, the checksum of the associated File packet or Directory packet is contained in the Root packet.  This is similar to the Directory packet. The checksums are in numerical order.

It is not allowed for the Root packet to contain Files or Directories or Links with duplicate names.  Each name must be unique.

There is only one Root packet for an InputSetID.  There can be multiple identical copies of this packet in the file.  (This is true for all packets.)

Note:  The Root packet's checksum represents a checksum for the entire input set.  This is because file data and metadata is reflected in the checksum of the File packets.  The directory contents and metadata are reflected in the checksum of each Directory.  And all of the above are reflected in the checksum of the Root packet.  

Note: Since the Root packet acts like a directory, its contents have the same restrictions as the Directory packet.  Notice, however, that permission packets are NOT allowed as options for the Root packet (but are for Directory packets).

Note: The Root packet's header contains the InputSetID, which is a checksum of the Start packet's contents.  The Start packet contains the checksum of the parent's Root packet.  Thus, the complete chain of ancestors is determined by Start/Root packets.  

Note: Some examples.  If the input set consisted of one file "/usr/bin/bash", it would be encoded: Root(absolute)->Directory("usr")->Directory("bin")->File("bash",...)   If it was one file "src/foo.c", it would be encoded: Root(relative)->Directory("src")->File("foo.c", ...).  The "->" indicates including the checksum of the packet on the right is written into the packet on the left.  

Note: Windows has two forms of absolute paths: "C:\dir\file.txt" and "\dir\file.txt".  The second one refers to a file on the current drive.  The first is encoded: Root(absolute)->Directory("C:")->Directory("dir")->File("file.txt", ...)  And the second: Root(absolute)->Directory("dir")->File("file.txt", ...).  Thus, clients on Windows will need to look for Directory packets with drive names at the first level inside an absolute Root packet.  When it happens, they must change drives accordingly.


#### File System Specific Packets

The following packets are used to contain the metadata for specific file systems.  Clients are not required to support any of them.  Clients MAY write the packets for the particular file system that the client is run on and may write additional ones.  Clients SHOULD support decoding the packets that they write.

The metadata often contains security-related features: ownership of files, etc..  Client authors need to take security seriously.  We do not want Par3 to become a method for hackers to attack our users' systems.  If a piece of metadata could be used to violate security, the default action of the client should be to ignore it or to query the user.  It is REQUIRED that the user's permission be granted for any action that might jeopardize their security.

In addition to the packet-specific information below, there is a separate section of this document devoted to security.  Client authors should follow it and investigate any common ways to hack their particular system.

Parchive 3.0 supports metadata for 2 file systems: a generic UNIX file system and FAT/FAT32/exFAT.  Parchive 3.0 supports some features of NTFS, like precise timestamps and hard and symbolic links, but NTFS's complete file permissions were too complicated to include in version 3.0.  Future versions of Parchive may support them.  Clients on an NTFS file system that need to preserve more than FAT-style permissions and hard/symbolic links will need to use another program to preserve them.  

The encoding client can write permissions for as many file systems as chooses.  It can write none or write both UNIX permissions for a file and also FAT permissions for the same file.  The decoding client can choose to ignore all file-system specific permissions.  If it chooses to support them, it should prefer the permissions for its current file system.  (That is, prefer the Par3 file's UNIX permissions when on a UNIX file system and FAT permissions on an FAT/NTFS system.)  If the permissions for the current file system are not in the Par3 file, the decoding client can attempt to translate the permissions in the Par3 file to the local system.  However, that should be undertaken with extreme caution, due to the potential for errors weakening security.


##### Link Packet

This packet represents a hard or symbolic link on UNIX and NTFS file systems.  (The FAT and exFAT file systems do not support links.)

The Link packet has a type value of "PAR LNK\0" (ASCII). The packet's body contains the following:

*Table: Link Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 1    | unsigned int | attributes |
| 2    | unsigned int | length of name in bytes |
| ?    | UTF-8 string | name of symbolic link or hard link |
| 4    | unsigned int | length of path in bytes |
| ?    | {UTF-8 string} |  path where NUL is the separator character |
| 1    | unsigned int | number of options (a.k.a. permissions) |
| 16*? | fingerprint hashes | checksums of packets for options |

The attributes is a bit field.  At the moment, only the least significant bit is used.  If it is 0, the link is a hard link.  If it is 1, it is a symbolic link.  All bits besides the least significant bit must be set to zero.

The link's name is encoded as the length of the link's name in bytes and the UTF-8 string containing the name.

Next are the length of the path in bytes and UTF-8 strings containing the path.  The path separator is the NUL character, the byte 0.  (In C, C++, and Java, it is written '\0'.)  If a path is an absolute path, the first character is NUL.  There is no NUL character at the end of the string.  Thus, a UNIX path "/usr/bin/bash" is encoded "\0usr\0bin\0bash", using the C convention of "\0" for the NUL character.  The path "src/foo.txt" would be encoded "src\0foo.txt".  (The previous strings do not follow the C convention of an implicit NUL at the end of the string.  There is no NUL at the end of the path.)  If the link is to a file in the input set, the names need to exactly match the names in the Directory and File packets.  (Note: Yutaka-Sawada claimed "Windows actually supports 32767 UCS-2 characters (65534 bytes) in paths via UNC naming.")

The final two fields hold the number of options and the checksums of the packets holding those options.  The number of options is a 1-byte value, like the File packet.  For a Link packet, the options are UNIX Permissions packets and FAT Permission packets.  There can be at most one of each type.   Future versions of Parchive may include more option packets (for example: NTFS permissions, etc.).  Clients can add their own custom packet types that can appear as Link packet options.  If the decoding client cannot find a packet with that checksum or does not recognize an option packet, the client can still recover the link.  Clients SHOULD warn the user if a packet with a particular checksum could not be found or if an option packet's type is not recognized.

Note: The length of the path is 2-byte unsigned integer, rather than a 1-byte unsigned integer, because paths can be longer than individual file/directory names.

Note: A path is necessary to identify a particular target file or directory.  A checksum of a File or Directory packet is not enough because duplicate files/subdirectories with the same name will have the same packet checksum.  Moreover, the link could be to a file or directory outside the input set. 

Note: Creating a link to file outside the input set is a serious security risk.  See the section of this document on security.

Note: For most UNIX systems, the permissions of symbolic links are ignored.  (The link's permissions are defined to be the same as that of the linked-to file.)  However, on MacOS and FreeBSD, symbolic links can have permissions different than their target, so they are supported in this file format.  



##### UNIX Permissions Packet

This packet holds the metadata from a generic UNIX system.  The same packet stores the metadata for files and directories.  It is based on Linux's EXT4 file system, but does not capture all the details of that system.  

The UNIX Permissions packet has a type value of "PAR UNX\0" (ASCII). The packet's body contains the following:

*Table: UNIX Permissions Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8      | signed int | atime, nanoseconds since the Epoch |
| 8      | signed int | ctime, nanoseconds since the Epoch |
| 8      | signed int | mtime, nanoseconds since the Epoch |
| 4      | unsigned int	| owner UID |
| 4      | unsigned int	| group GID | 
| 2      | unsigned int	| i_mode |
| 1      | unsigned int | length of string |
| ?      | UTF-8 string | name of owner |
| 1      | unsigned int | length of string |
| ?      | UTF-8 string | name of group |
| ?*(4+?) | {2-byte unsigned int, UTF-8 string, 2-byte unsigned int, UTF-8 string} | xattr name-value pairs |

The times are all in nanoseconds since the Epoch, UTC.  They can hold EXT4's extended values.

Owner UID, Group GID are 32-bit values, also to hold EXT4's extended values.

The i_mode value contain the lower 12 bits of EXT4's values for the i_mode.  (The file type is encoded elsewhere in Par3's packets.)  The top 4 bits are all zeroes.  See https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#Inode_Table   

The owner and group are also encoded as strings.  The decoding client can decide if owner/group are determined by UID/GID or by username/groupname.  (This is also how "tar" works.)

The extended attributes are stored as name-value pairs.  Both the name and value are stored as a 2-byte length of string followed by the UTF-8 contents of the string.  The number of extended attributes is implicit, based on the length of the packet.

The same UNIX Permissions can be applied to multiple files, directories, or links.  That is, the checksum for a UNIX Permissions packet can appear in multiple File, Directory, or Link packets.

Note: Different UNIX systems have different limits on the size of xattrs.  Linux's interface, the Virtual File System (VFS), limits all xattr names to fitting in 64kB and each value to fitting in 64kB.  EXT4 limits everything to fitting in 4kB.  BTRFS limits everything to 16kB.  Some file systems have no limit.  The choice of supporting values of only 16kB in length is probably sufficient for most uses.

Note: The "atime" field is the time the file was last accessed.  Obviously, the Par3 client will be accessing the files.  The encoding client can choose to store the previous access time or the time of access by the Par3 client.  The decoding client can choose to use the time from the UNIX Permissions packet or the current time.  (This behavior is similar to the GNU version of the program "tar" with use of the flag "--atime-preserve".)

Note: The "ctime" field is the time the file's metadata was last changed.  Clients are NOT expected to write the ctime field on files created.  (Changing the ctime requires the extraordinary measures of either changing the system clock or writing the filesystem as a raw device.)  The "ctime" field is included so "incremental backups" can detect if the metadata has changed since the previous UNIX Permissions packet was generated. 

Note: If the encoding client wants to use some parts of this packet and not others, the default values for the unused parts are set as follows:

*Table: UNIX Permissions Packet Unset Values

| Field | Unset Value |
|------:|------------:|
| atime, ctime, mtime | 2^64-1 (maximum unsigned value) |
| UID, GID | 2^32-1 (maximum unsigned value) |
| i_mode | 0x0180 (owner read+write) |
| owner name, group name | empty string | 
| xattr | empty list |

Note: Decoding clients should check for file timestamps that are greater than the current time.  Some systems may not behave well with files "from the future".  Decoding clients can always adjust the timestamps backwards to the current time.


##### FAT Permissions Packet

This packet holds the most of the metadata from a file or directory on a FAT/exFAT file system and some of the metadata for an NTFS file system.  It is based on the Windows API calls.

The FAT Permissions packet has a type value of "PAR FAT\0" (ASCII). The packet's body contains the following:

*Table: FAT Permissions Packet Body Contents*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 8 | unsigned int | CreationTimestamp | 
| 8 | unsigned int | LastAccessTimestamp |
| 8 | unsigned int | LastWriteTimestamp |
| 2 | bit field    | FileAttributes |

The "Timestamp"s are 100s of nanoseconds since Jan. 1, 1600, UTC.  Timestamps use the UTC timezone.

The attributes byte is a bit field.  The bits are:

*Table: Attributes bit field*

| Bit Index | Attribute |
|----------:|:----------|
| 0 | ReadOnly |
| 1 | Hidden |
| 2 | System |
| 3 | not used (was "Volume") |
| 4 | not used (is "Directory", but that data is stored elsewhere) |
| 5 | Archive |
| 6 | not used (was "Device") |
| 7 | not used (was "Normal file", but that data is stored elsewhere) |
| 8 to 12 | not used |
| 13 | Content not indexed |
| 14 to 16 | not used |

Unused bits in the attribute bit field must be set to zero.

The same FAT Permissions can be applied to multiple files, directories, or links.  

Note: On FAT, all timestamps are only accurate to 2 seconds.

Note: On exFAT, the CreationTimestamp and LastWriteTimestamp are accurate to 10 milliseconds.  The LastAccessTimestamp is accurate to 2 seconds.

Note: On NTFS, Windows only guarantees that LastAccessTimestamp is accurate to 1 hour.  

Note: The "LastAccessTimestamp" field is the time the file was last accessed.  Obviously, the Par3 client will be accessing the files.  The encoding client can choose to store the previous access time or the time of access by the Par3 client.  The decoding client can choose to use the time from the FAT Permissions packet or the current time.  (This behavior is also optional in GNU version of the program "tar" by use of the flag "--atime-preserve".)

Note: FAT and exFAT file systems store the UTC timezone offset for all timestamps.  Those offsets are not preserved in this packet.  The timestamps are all in UTC.  Decoding clients can choose the timezone offset to write to the file system.

Note: Windows supports additional file attributes, including: sparse (bit 9), compression (bit 11), and encrypted (bit 15).   These bits are not supported by Par 3.0.  (These bits cannot be set using the SetFileAttributesA API call.)  Clients SHOULD warn users when these will not be preserved.  
Note: If the encoding client wants to use some parts of this packet and not others, the default values for the unused parts are set as follows:

*Table: FAT Permissions Packet Unset Values

| Field | Unset Value |
|------:|------------:|
| CreationTimestamp, LastAccessTimestamp, LastWriteTimestamp |  2^64-1 (maximum unsigned value)  |
| FileAttributes | 0 | 

Note: Decoding clients should check for file timestamps that are greater than the current time.  Some systems may not behave well with files "from the future".  Decoding clients can always adjust the timestamps backwards to the current time.


## Clarifications and Commentary 

### Security

Security is a major issue for Parchive clients.  Users will probably execute the client on untrusted files, downloaded from strangers.  We do not want Parchive to be a means for hackers to attack a system.

There are three major ways for hackers to attack using a Par3 file.  The first is to get the client to run untrusted code.  The second means of attack is to get the client to create or modify important files, such as overwriting the password file.  The last attack is a "denial of service" where the attacker fills the hard drive completely.  (Most operating systems require some empty space on a drive to operate.)   

The first means of attack is for hackers to get the client to run untrusted code.  The most common example of this is a "buffer overflow attack".  The design of the Par3 file format is made to avoid buffer overflow attacks.  Every region of data has an explicit lengths.  Strings are not NUL-terminated.  This forces client writers to think about the sizes of buffers and how they use them.

Client writers can find buffer overflows and other bugs using "fuzzing".  Fixing those bugs will prevent hackers from being able to trick the client into running untrusted code.

The second means of attack is to hack the file system.  That is, to have the client modify the data or the permissions of an important file such that the system will read/execute the file or the user will unintentionally execute it.  (We accept that the user can always intentionally run a program sent in an untrusted Par3 file.)  An example of a hack of the file system is to overwrite the file containing usernames and passwords.

Avoiding file system attacks takes care.  Especially if the client is designed to run on multiple file systems and OSes.  Each system has different vulnerabilities and all of them must be taken into account.

One part of preventing these attacks is confirming that filenames are valid filenames.  A filename should not contain a '\0' in the middle of it.  It should not be a path (for example: not contain "/" on a UNIX system or "\" on a Windows system.  MacOS also accepts ":".).   The filename should not violate conventions (for example: on UNIX, be named "." or "..".).  It should not reference a networked filename or device name.  (For example: Windows does not allow "COM0", "LPT0", and many more.)

Slightly off the topic of security, this is probably a good place to recommended that users be warned when they create Par3 files containing names that are incompatible with Windows, Mac, or Linux systems.

Reserved filenames:
- Windows: "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", and "LPT9".
- Linux: "." and ".."
- MacOS: "." and ".."
  
Characters not allowed in filenames:
- Windows: < > : " / \ | ? * 
- Linux: / \0
-  MacOS: / \0   (Older versions used : as a special character)

Other considerations:
- Window's shell uses: % ^ ; \t ' "
- UNIX shells use: [ ] * ? ; | & ! ~ # < > ' ` " $ =
- UNIX shells hide files starting with "."
- UNIX programs have difficulty with files starting with "-"
- Difficult to type white space: \t \n \r \v \f
- White space at start or end of filename, including spaces.

Another part of preventing file system attacks is to validate paths.  For paths, major attacks will come by referencing a file using an absolute path ("/etc/passwd" or "C:\Windows\System32\Config") or escaping a subdirectory ("../../etc/passwd" or "..\..\Windows\System32\Config").   (Note: On Windows, an absolute path can start "C:\" or "\" or "\\" for example. For UNIX, that means one starting with "/" or "//" or "~". For Mac, one can also start with ":".  There may be other formats!)  It is REQUIRED that the client get user approval before using an absolute path or using a feature like ".." in a path.   For a GUI, this approval can come via a dialog box saying something like "This Par3 file is writing to an absolute path.  This is dangerous, because it can overwrite system files like your password file.  Do you want to allow this?"  For a command line tool, the approval can come via a command line option.  The default should always be to not allow this behavior.

Clients are also REQUIRED to ask for permission when linking to files outside a subdirectory.  That is, if the link target contains an absolute path or uses a feature like "..".

Other attacks can come through file attributes.  It is doubtful that setting a file to be "read-only" or changing its creation time will be part of an attack.  But some attributes are means of attack.  Clients SHOULD warn users when a file is marked "executable".  Especially if the file is added to a place where users execute command.  (For example: on UNIX, a hacker might write a program called "ls" into a directory in the user's PATH.)  Clients need to be careful when setting the owner of a file.  Client writers need to know the common attacks on their platforms.  (For example: on UNIX, any file with both the "others may write" permission and the "Set UID" permission is a security hazard.)  Clients are REQUIRED to get approval for any action that might compromise security.

The third and last attack is one that fills up the entire file system.  This is a "denial of service" attack, because most OSes cannot run when the file system is full.  This attack is a possibility because it is not hard to create the Parchive equivalent of a "ZIP bomb": a small file that writes a stupendous amount of data to the file system.  Client writers should also worry about this attack, because user may accidentally fill up their entire file system.  

Client writers can avoid this error by checking the amount of free disk space before writing.  Client writers should also be aware of OS return values that indicate that free space is exhausted.  (For example: on Linux, the write() system call can generate errors ENOSPC and EDQOUT.)

Earlier versions of Parchive avoided including file permissions in the standard, because security issues are difficult to get right.  Please take security seriously.  


### Alignment

In Par2, the packets were forced to be "4-byte aligned".  That is, packet lengths were always a multiple of 4 and the first byte of X-byte integers always had an index in the packet that was a multiple of X.  Par3 has dropped the requirement that packets be aligned.

Still, some processors --- either old ones like ARMv5 or new ones with SIMD instructions --- have significantly higher performance when values are aligned in memory.  Par3 dropped the alignment requirement because there isn't a single alignment that works for all these processors.  ARMv5 requires 4-byte alignment and some x86 AVX instructions require 64-byte alignment.

Par3 does not require packets to be aligned, but a client author can introduce alignment to Data packets and Recovery Data packets written by their client by choosing an appropriate block size and inserting zero-byte padding before these packets.  Remember, though, that a client must be able to read every Par3 file and not every client will generate aligned packets.  And, in any case, alignment in any file can be thrown off when a byte is lost or gained during transmission.  So, while a decoding client may run faster when a packet is aligned, it must still work properly if the packets are not aligned.  

In short, a client author can introduce alignment into their own files to increase performance, but cannot require alignment in all files.  


### Galois Field Encoding 

Parchive 3.0 supports any Galois field that is a power of 2^8.  That is, any Galois field that fits neatly in one or more bytes.  Clients must support every possible Galois field.

Clients are expected to optimize performance for specific Galois fields.  Some likely targets for optimization are:

*Table: Common Galois fields*

| Size (bits) | Generator (hexadecimal) | 
|------------:|------------------------:|
| 8   |          0x11D |
| 16  |          0x1100B |
| 128 |          (1 << 128) + 0x43 |

Note: The 8-bit Galois field is used by many error correction applications, including some implementations of RAID6.  

Note: The 8-bit Galois field with generator 0x11B is used by AES encryption and is supported by the x86 instruction GF2P8MULB.  However, it tends not to be used for error correction, because it does not have a "primitive element".   (See https://en.wikiversity.org/wiki/Talk:Reed%E2%80%93Solomon_codes_for_coders#The_magic_number_0x11D_(0b100011101))

Note: The 16-bit Galois field is the same as in Par 2.0.

Note: All 64-bit Galois fields are supported by the x86 instruction CLMUL.

Note: The 128-bit Galois field is implemented by Intel in this white paper:
https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf

Note: The ARM processor has an instruction extension called "NEON" with a VMULL instruction.  VMULL.P8 will do eight 8-bit Galois field multiplications at once.


### Rolling Hash

The rolling hash is intended to find input blocks that have moved inside an input file.  The rolling hash is fast, but imperfect.  Thus, the rolling hash matches, the client will test the possible input block with the slower-to-compute fingerprint hash.  But, when data is repetitive, this can lead to a problem.

The problem with repetitive data is that many locations can match the rolling hash.  Then, the slower fingerprint hash is computed at all those locations and the process of finding input blocks slows to a snail's pace.

This problem doesn't occur if the user compressed the data before writing the Par3 file, because a compressed file is almost random.  But the decoding client can't rely on the data being compressed.

The decoding client can solve the problem of many blocks matching the rolling hash in many ways.  One approach is to count the number of matches for each rolling hash value.  If there many matches over a small area of the file, the client can ignore that rolling hash value for a while.

Another approach is to scan a file twice.  The first pass looks for all blocks that match the value of a rolling hash.  The second pass computes the fingerprint hashes, prioritizing the blocks that match a unique rolling hash value and the blocks that do not overlap other blocks.  


### Chunking and Deduplication

Par3 allows "deduplication".  If an encoding client finds multiple copies of the same data in different input files (or inside the same input file), the client only needs to store one copy of it in the input blocks.  This improves the chance of recovery for two reasons.  First, when there are multiple copies of an input blocks in the original files, if any of them survives undamaged, the others can be recovered by copying the good version without consuming a recovery block.  Second, if all copies are lost, it only consumes a single recovery block to fix multiple errors.  So, when input files duplicate data, deduplication is a powerful feature to improve the chance of recovery.

Deduplication is enabled in Par3 by chunks.  If data is duplicated in multiple files or in the same file, the same chunk description can appear multiple times in File packets or in a single File packet.  "Deduplication" is not required during encoding --- an encoding client can always encode each file as a single chunk.  But when decoding, clients are required to support multiple chunks and do recovery with them.  

As an example, an encoding client might use a 2,000 byte block size and have two input files A and B, where A is 16,000 bytes long and follows the pattern "abc1234567890def" and B is 17,000 bytes long and follows the pattern "tuvw1234567890xyz".  A client that does not deduplicate would encode each of these files as a single chunk.  File A's chunk would contain 8 input blocks ("ab", "c1", "23", "45", "67", "89", "0d", "ef") and File B's chunk would contain 9 input blocks ("tu", "vw", "12", "34", "56", "78", "90", "xy", "z\0").  Any redundant data would protect those 17 input blocks.

An encoding client that deduplicates could identify that "1234567890" is the same in each file.  The file A would be broken into 3 chunks: "abc", "1234567890", and "def".  The file B would also be broken into 3 chunks: "tuvw", "1234567890", and "xyz".  When the chunks were chopped into input blocks, those would be: "ab", "c\0", "12", "34", "56", "78" , "90", "de", "f\0", "tu", "vw", "xy", "z\0".  Thus, with deduplication, there would only be 13 input blocks.  Not only would there be 2 copies of 5 of the input blocks in the input files, but the redundancy data would only have to protect 13 input blocks and, therefore, be more likely to recover from a problem.  

(Note: A client could also packs the tails of two chunks into the same input blocks.  If the tails "c" and "f" were stored in the same input block, that would mean there were only 12 input blocks!)

Clients that want to find duplicate data can do it in three possible ways.  One technique is called "content-defined chunking".  It breaks files into variable-length chunks based on their contents and then uses fingerprint hashes to identify duplicate chunks.  The second technique uses rolling hashes of new data to identify block-sized pieces that are duplicates of existing input blocks.  When a duplicate block is detected, the duplicate becomes the start of a new chunk.  The chunk continues as long as the following block-sized pieces continue to duplicate the subsequent existing input blocks.  The third technique is to query another system for the duplicate data.  Some version control systems or file systems record duplicate data.


### Compression 

Parchive 3.0 does not include compression, beyond deduplication.  There are many compression algorithms and the right compression algorithm depends on the data.  Users will get the most benefit by using video compression for video, audio compression for audio, etc..

Despite common use of RAR for compression and splitting with Par2, RAR is rarely needed.  See https://github.com/animetosho/Nyuu/wiki/Stop-RAR-Uploads

Using compression can interfere with deduplication.  When data is duplicated in many locations, a compression algorithm may encode each copy differently.  When compressing highly duplicated data, there are two solutions.  One is to deduplicate the data using Par 3.0, then compress the data, then protect the compressed file using Par 3.0 a second time.   The other approach is to use a compression algorithm that collaborates with Parchive's deduplication.  For gzip, the option "--rsyncable" will slightly impact compression, but allow deduplication to work. 


### Sparse Matrices 

With a sparse matrix, it is faster to calculate recovery blocks, but the user has to accept a slightly higher chance of not recovering from extreme cases.

A sparse random NxN matrix with at least N*ln(N) non-zero elements has rank N-K for some small K.  When ln(N)>3 or, equivalently N>20, large values of K are very very rare.  Invertible matrices have rank N, so these sparse random matrices with rank N-K are very very close to being invertible.

To be specific about K and the rank, the probability for the rank being less than N-K for a given K is proportional to 1/(g^K) where g is the number of unique Galois field values.  Thus, if matrix's elements are from a 1-byte Galois field with 256 values, the probably that the rank is less than N-3 is proportional to 1/(256^3) or less than one-in-a-million.  For details, see "The Rank of Sparse Random Matrices over Finite Fields" by Blomer, Karp, and Welzl.

Thus, if the recovery submatrix (called "C_good,bad" earlier) is NxN with at least N*ln(N) randomly non-zero elements and ln(N)>3 (or, equivalently, N>20), we can recovery almost all the input blocks.  Specifically, N-K of them.  And, if we augment the random matrix with K recovery blocks generated from a Cauchy matrix, which can recover any missing input blocks, we are very very likely to recover all the input blocks.  

Given this, how many random recovery blocks and Cauchy recovery blocks should be generated?  If there are B input blocks and we want them to survive a maximum perfectly-random failure rate F and use constant K, then the number of sparse random recovery blocks should be `B\*F/(1-F)` and the number of Cauchy recovery blocks should be K/(1-F).  The probability of a non-zero element in the sparse random matrix must be at least ln(N)/N, where `N=B\*F`.  Please keep in mind that the math only works when ln(N)>3 or, equivalently, N>20.  *WARNING: the math in this paragraph was done using expected values, not proper probability distributions, and may under estimate the probability of some events, such as losing multiple Cauchy recovery blocks, which could affect the probability of recovery.*

If it feels wrong to increase the probability of failure, recall that for any matrix, it must fail if B-1 or fewer input and recovery blocks arrive.  Using a sparse matrix, rather than a Cauchy, can run up to N/ln(N) times faster.  Users that can store/send a few additional recovery blocks can get much faster performance with a minuscule increase in failure to recover.


### Incremental Backup 

The Parchive 3.0 specification allows new Par3 files to reuse the recovery data in existing Par3 files.  That is, the recovery data from an old input set can be used to help recovery the files of new input set.  This is (badly) called "incremental backup".  This is different from deduplication, which reuses data inside the same input set.  (Although, as you'll see, deduplication can be used within an incremental backup.)

An incremental backup only makes sense when the new set of input files has a lot of overlap with the previous set of input files.  The most common usage is when a user made a Par3 file, then added (relatively few) files to the directory tree or renamed some files, and now wants to make a new Par3 file.  That new Par3 file, the "incremental backup", can reuse the file descriptions and recovery data in the existing Par3 file.  An incremental backup can contain any changes, including modified files or deleted files, but it becomes less efficient with more and larger changes.

I'll use the term "parent" to refer to the pre-existing Par3 file(s) and "child" to refer to the new Par3 file(s). The child may also be called the "incremental backup".

A client creates an incremental backup by writing the InputSetID of the parent into the child's Start packet.  The child's Start packet must also have the same block size, Galois field, and Galois field generator as the parent's.

The child will have a new Root packet, which determines the input set for the incremental backup.  The child can reuse File, Directory, and file-system specific packets from the parent to encode that input set.  The child will have to contain new File packets for all the files that have changed and new Directory packets when the contents of the directory or any of its subdirectories have changed.  So, if a single file has changed, the child will be one new File packet, a new Directory packet for every directory above the file, and a new Root packet.

If any file data has changed or been added, the child will have new input blocks.  These are assigned indices greater than any index used by a parent's input block.  The lowest input block index that went unused by the parent can be found in the parent's Root packet.

If a new file's contents are similar to a previous version, the encoding client can do deduplication to reuse the data stored for the parent's version of the file.  See the section on "Chunking and Deduplication" above.  The child's File packets' chunk descriptions will reference the input blocks of the parent's version of the file.  Reusing data from the parent's input blocks is not required, but can save a lot of storage and significantly increase the probability of a recovering data.


### Par Inside Another File

Par3 packets can be used to protect the file in which they are stored.  They cannot protect all of the file, because Par3 packets only protect the input data and not themselves.  When Par3 data is used inside another file format to protect it, we call it "Par inside".  So, if Par3 data protects a ZIP file, we call it "Par inside ZIP".

An example of using Par-inside is with the ZIP file format.  The ZIP file format stores compressed files at the front and the list of all files at the end, but, inbetween, space can be used for any data without affecting the ZIP file's contents.  Par3 packets can put in this space.  The Par3 packets can protect the start and end of the file, where ZIP stores its data.  This way, if the file ever gets damaged, the Par3 packets can be used to fix the ZIP data.  It is a file that contains data to repair itself.

To make Par-inside work, the Par3 packets need to contain one File packet, which refers to the file itself.  Thus, the name in the File packet must match the name of the file.  The File packet's chunk descriptions must contain checksums for the protected portions of the file and must have zeroed checksums for where the Par3 packets will be written into the file.  In the case of the ZIP file, only the start and end of the file would have chunk descriptions with checksums.  The middle of the file, where the Par3 packets are stored, would have a chunk description with a zeroed checksum.  Obviously, External Data packets would be used and not Data packets.

It is possible to use Par3 packets to protect the Par3 packets of a different input set.  This is useful because some parts of the Par3 file are not redundant.  When we use Par to protect the non-redundant parts of a Par3 file, we call this "Par inside Par".  Thus, instead of repeating vital packets (Start, Matrix, Root File, Directory, and Root packets), the sections of the file containing them would be protected using "Par inside".  The Par-inside packets would be distinguishable from the "outside" Par3 packets because they would have a different InputSetID.  

The "inside" Par3 packets cannot protect themselves.  The vital "inside" Par3 packets would still need to be repeated and spread through out the file.  The "Par inside Par" concept only makes sense if the vital "outside" Par3 packets take up a lot of space in the Par3 file.   For example, when storing a large number of files.  Then, the space used by vital "inside" Par3 packets would be much smaller than the vital "outside" Par3 packets and repeating the vital inside Par3 packets would shrink the overhead and minimize the amount of data could make the Par3 file unusable.


## Conventions

The above is the official spec.  It is what all clients must implement.  This section discusses conventions, which are what most clients will want to do, so that users have a common expectation of how a Parchive client behaves.

Par3 files should always end in ".par3". For example, "file.par3". If a file contains recovery blocks, the ".par3" should be preceded by ".volXX+YY" where XX is the number of previous recovery blocks and YY represent the number of recovery blocks in this file. For example, "file.vol20+10.par3" means this starts with the 20th recovery block and contains 10 recovery blocks.  More than 2 digits should be used if necessary.  Any numbers that contain fewer digits than the largest exponent should be preceded by zeros so that all filenames have the same length. For example, "file.vol075+10.par2".  Numbers should start at 0 and go upwards.

If a Par3 file contains input blocks, the ".par3" should be preceded by ".partXX+YY", where XX is the number of previous input blocks and YY is the number in this file.  

If multiple Par3 files are generated, they may either contain a constant number of blocks per file (for example: 20, 20, 20, ...) or exponentially increasing number of blocks (for example: 1, 2, 4, 8, ...). Note that to store 1023 blocks takes 52 files if each has 20 blocks, but takes only 10 files with the exponential pattern.

When generating multiple Par3 files, it is expected that one file be generated without any Recovery Data packets and containing all the packets needed to verify correct transmission of the files.  That is, contain the Start, External Data, File, Directory, and Root packets.  It may also contain the Matrix packets.  This file is often called the "Index File".

The other files should either (1) include duplicates of all those vital packets or (2) use "Par inside Par" to protect damage to them.  "Par inside Par" is creating using Par3 packets with a different InputSetID.  That input set would contains the Par3 file itself as an input file.  "Par inside Par" is useful when the space taken up by the vital packet is large.  Duplicating it would take up a lot of space.  When using "Par inside Par", the outer Par3 data would only need to protect 1 file and duplication of its vital packets would not take up much space.

If just a single Par3 file is generated, it is expected that the vital packets are repeated multiple times and scattered through out the file. (Once again, repeating data that cannot be recovered.)  Or, "Par inside Par" data can be generate and scattered through out the file.

Recall that all files must contain a creator packet.



## Conclusion

Parchive 3.0 is a big step over Parchive 2.0.  It has new capabilities (deduplication, incremental backups, Par-inside), expanded capabilities (more than 2^16 blocks/files) and is very flexible (any Galois field and any code matrix).  We hopes that Parchive 2.0's current users enjoy the new features and we hope that Par 3.0 finds new uses and users.  


## Appendix A: License

Unfortunately there is not a standard license for file formats.  Thus, this is a custom license.  It is very restrictive, but may be loosened in the future.

The authors reserve all legal rights to this document, including copyright and servicemarks, with the following exceptions:

- Everyone is free to copy this document unchanged.

- Everyone is free to write programs that implement this file format.

- Everyone is free to promote programs that implement this file format using such language as "Par3", "Parchive 3", etc. and using files ending in ".par3", or similar.

- If any person or company that promotes a program claiming to implement this format and using such language as "Par3", "Parchive 3" or files ending in ".par3" or similar, everyone is allowed to sue that person or company for damages if the program does not comply with this format.  Damages should be large enough to deter persons or companies from falsely using such language.  Damages should be large enough to incentivize the enforcement of this clause.

- Persons and companies are allowed to create and distribute derivatives of this file format.  They are not required to publish the details of their format.  They are not allowed to claim to be this format (such as using "Par3") or the rightful heir to this file format (such as using language like "Par3.1", "Parchive 4" or files ending in ".par5", or similar).  

- Any rightful heir to this file format, which is allowed to use such language as "Par3.1", "Parchive 4", or files ending in ".par5", or similar, must be done using an open process, carry similar right as contained in this document, and to involve Michael Nahas, if possible.  For a definition of "open process", judges are instructed to consult Lawrence Lessig, the Creative Commons, the Software Freedom Law Center, and the Free Software Foundation.

This was written by a non-lawyer, Michael Nahas.  Any judge should interpret this license from its intent and not as precise legalese.


## Appendix B: Example Application-Specific Packet Type

Say the author of "NewsPost" wanted to add his own packet type - one that identified the names of the Usenet messages in which the files are posted. That author can create his own packet type. For example, here is the layout for one where the Usenet messages are identified by a newsgroup and a regular expression which all matches the names of the Usenet articles.

The packet has a type value of "NPstMSGS" (ASCII).  The author chose the prefix "NPst" for his client, "NewsPost", which prevents collisions with other clients.  The packet's body contains the following:

*Table: Example Application Specific Packet*

| Length (bytes) | Type | Description |
|---------------:|:-----|:------------|
| 16 | fingerprint hash | The checksum of the File packet |
| 2 | unsigned int | The length of the string (in bytes) containing the name of the newsgroup. |
| ? | UTF-8 string | The name of the newsgroup. For example, "alt.binaries.multimedia".|
| 2 | unsigned int | The length of the string containing the regular expression.|
| ? | UTF-8 string | A regular expression matching the name of articles containing the file. For example, "Unaired Pilot - VCD,NTSC - (??/??)". |


## Appendix C:  Example of a Deduplication Algorithm.

There is a single-threaded algorithm that uses a window of size `2*blocksize-1` to do deduplication on new files.  The client must store the rolling hashes and fingerprint hashes of all existing blocks.  The client must also store a "preliminary chunk", which will be the next chunk but isn't final yet.  

The algorithm is best explained by working through an example.  To make the example manageable, we'll use a blocksize of 6 bytes and assume the "inline data" feature for tails does not exist.  Before starting, we'll assume the client has already processed as file with contents "aaabbbcccdddeeefffggghhhiiijjj" as a single chunk.  The 6-byte input blocks would be: 0: "aaabbb", 1:"cccddd", 2:"eeefff", 3:"ggghhh", 4:"iiijjj".

The algorithm will find duplicate blocks in a new file with contents "aaabbbcccdddeee000111222333fffggghhhiiijjj", where "000111222333" has be inserted into the middle of the old file.  The algorithm works by sliding a window over the file.  Since the block size is 6, the window size is 2*6-1 = 11 bytes. When we start to slide the 11-byte window over a file, its contents are:

```
W=[aaabbbcccdd]
```
The client scans the window using the rolling hashes of all the existing blocks (0 to 4). If there are any matches, the client confirms that it is the existing block using the existing fingerprint hashes.  When the client does that on this window, it finds that "aaabbb" matches block 0. So that becomes the start of a preliminary chunk {length=6+?, firstblockindex=0, tail?} and the client moves the window beyond that block.

```
W=[cccdddeee00]
```
The client scans the new window with the existing hashes. The first complete block it finds is "cccddd". That is a continuation of the existing preliminary chunk, so it updates the preliminary chunk to {length=12+?, firstblockindex=0, tail?} and moves the window.

```
W=[eee00011122]
```
The client scans this window with the existing hashes. It finds no matches. There is a preliminary chunk that it has been working on, so the client checks if it has a tail. The last block in the preliminary chunk was block 1, so the client checks if the start of the window matches the start of the next block, which is block 2. This requires loading block 2 back into memory, which is expensive, but is necessary to find the tail. When it compares the start of the window to the start of block 2, it finds that "eee" is common to both. The client declares that that is the tail of the preliminary chunk. The client finalizes the chunk as {length=15, firstblockindex=0, tailblockindex=2, tailoffset=0}. The client moves the window past the tail.

```
W=[00011122233]
```
The client scans and finds no matches with existing blocks. It has no preliminary chunk, so it start a new preliminary chunk with a new input block. {length=6+?, firstblockindex=5, tail?} The client stores the rolling hash and fingerprint of the new block. The client moves the window past the new block.

```
W=[222333fffgg]
```
The client scans and finds no match. The client declares this a new block. It adds it to the end of the preliminary chuck and gets {length=12+?, firstblockindex=5, tail?}. It moves the window.

```
W=[fffggghhhii]
```
The client scans and finds an existing block, block 3, at offset 3. That existing block will become part of a new chunk, so the client has to finalize the existing preliminary chunk. The question is, what does the client do with the "fff"? Before writing "fff" into a new block, the client can recognize that "ggghhh" is in block 3 and that "fff" might be present at the end of block 2. So, it loads block 2 into memory and compares the end of block 2 to "fff". When it finds a match, the client finalizes the existing preliminary chunk as {length=15, firstblockindex=5, tailblockindex=2, tailoffset=3}. (If the end of block 2 did not match "fff", the tail would have been written into the first 3 bytes of block 7 and the finalized chunk would be {length=15, firstblockindex=5, tailblockindex=7, tailloffset=0}.) The client can now start a new preliminary chunk with the block it found: {length=6+?, firstblockindex=3, tail?}. It moves the window after the found block.

```
W=[iiijjj]
```
The scan says this is block 4. It is a continuation of the existing preliminary block. That becomes {length=12+?, firstblockindex=3, tail?}. The client moves the window.

```
W=[]
```
This is the end of file. The client finalizes the preliminary block as {length=6, firstblockindex=3}

So the chunks are:
```
{length=15, firstblockindex=0, tailblockindex=2, tailoffset=0}
{length=15, firstblockindex=5, tailblockindex=2, tailoffset=3}
{length=6, firstblockindex=3}
```

The above algorithm is single-threaded and requires reloading some blocks into memory after they've been processed.  However, reloading has to happen with any algorithm. The good news is that reloading only happens after an existing block has been identified, so if the process is slow, it is because deduplication is actually happening. That is, the user gets something for the delay.

The above algorithm would not work in parallel.  A similar parallel algorithm requires three passes over each file.  In the first pass, for every file, the client computes the rolling hash and fingerprint hash at block-size offsets. (That is, as if the files were each a single chunk and chopped into block-size pieces.) The second pass would be similar to the single-threaded algorithm: running a rolling hash over every file and identify the matches to the blocks found in the first pass. The second pass would also identify the "tails" before and after the matching blocks. After the second pass, the client would run a fast single-threaded calculation where it decided what data would be put into which input blocks. After that, there would need to be a third pass, where the recovery data was calculated using the input blocks and their indexes.

Note: Technically, the calculation of "deciding what data would be put into which input blocks" is an optimization problem.  Finding the solution that uses the absolute minimum number of input block is probably NP-Complete.  That is, the best known algorithms are all really slow in the worst case.  But there are fast algorithms that get very good solutions, even if they cannot be guaranteed to be optimal in every case.  



## Appendix D:  How many repetitions of vital packets?

Some Par3 packets are vital packets: you need to have them to recover the input data.  These inclue the Start Packet, File Packets, Root Packet, etc..  These vital packets can be protected by Par-inside-Par or by repeating the vital packets, with the hope that at least one copy survives.  If the client author wants to do repetition, how many copies are necessary?

We want all vital packets to survive storage or transimission with very very high probability. If there are N copies of a vital packet and each has a 5% chance of not arriving, the probability of that that packet not arriving is 0.05^N. If there are K different vital packets, the chance of failure is K*0.05^N.  To make the formula more general, let's replace 0.05 by a per-packet failure rate F to get the formula: K*F^N.

If we want failure to receive all packets to be less than 1 in a million, you want:

K*F^N < 0.000001.

Basic manipulation gets us:

F^N < 0.000001/K

log(F^N) < log(0.000001/K)

N*log(F) < log(0.000001) - log(K)

and because log(F) <= 1, the result is:

N > (log(0.000001) - log(K))/log(F)

The above formula can be generalized by replacing 0.000001 (the 1-in-a-million chance) with any level of assurance that the client wants to provide.  For a 1-in-a-billion chance of failure with 1000 vital packets and a 10% failure for a packet to arrive, you only need 12 copies of each packet.  

The value for F can be determined by the user's input to the client.  If the user asks for recovery data that is 4% of the size of all input data, then F=0.04.

Notice that that the above formula is a minimum number of copies of each packet and it assumes the packets have a random and equal chance of being damaged.  This is only achieved if the vital packets are perfectly randomly distributed inside the Par3 files.  If vital packets are not randomly distributed in the Par3 files, a client will want to include more copies.  


