This is a command-line Windows program to compute disk usage.

Using it is very easy, for example:

         wimboot-analyze D:\

Unlike other disk usage programs, this will report statistics about how much
data is externally backed with the help of the WOF (Windows Overlay File System
Filter) driver added in Windows 8.1.  This includes, for example, files that are
backed by a WIM archive for a "WIMBoot" setup (see
http://technet.microsoft.com/en-us/library/dn594399.aspx).

Additional notes:
    - If there are multiple WIM files backing files in the scanned
      volume, the program will print a breakdown by WIM file.
    - The program will also print some statistics about named ("alternate")
      data streams.
    - The program will handle long paths.
    - Locked and other inaccessible files will be excluded, but a warning
      message will be printed for each such file.
    - The program will not follow reparse points, such as symbolic links,
      junctions, and NTFS volume mount points.

This distribution includes the full source code.  The license for both source
and binary is stated at beginning of wimboot-analyze.c.
