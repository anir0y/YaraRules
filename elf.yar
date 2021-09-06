/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-09-06
   Identifier: temp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MSF_ELF {
   meta:
      description = "MSF ELF detection"
      author = "Mentor"
      reference = "https://blah.bah"
      date = "2021-09-06"
      hash1 = "0668c7b76f532225a19a511f1d7c9769759e220d33e61e8b9ba861e0e50a3292"
   strings:
      $s1 = "AYPj)X" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1KB and
      all of them
}

