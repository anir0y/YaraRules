/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-09-06
   Identifier: samples
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule custom_rules_for_MSF {
   meta:
      description = "samples - CUSTOM RULES"
      author = "Mentor"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-09-06"
      hash1 = "21fb8c400d6193c9fbca581c7c7f61113aa13dd631798aa054ff47b172db8478"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = "AQAPRQH1" fullword ascii
      $s3 = "AXAX^YZAXAYAZH" fullword ascii
      $s4 = "Rich}E" fullword ascii
      $s5 = "A^PPM1" fullword ascii
      $s6 = "}(XAWYh" fullword ascii
      $s7 = "@.tucq" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule reverse2 {
   meta:
      description = "samples - file reverse2.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-09-06"
      hash1 = "b5d8af5b0cacfac18a0698fd405197437527f28b7fd317ebc05907749f395714"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = "VPAPAPAPI" fullword ascii
      $s3 = "AQAPRQVH1" fullword ascii
      $s4 = "AXAX^YZAXAYAZH" fullword ascii
      $s5 = "Rich}E" fullword ascii
      $s6 = "@.rlkt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      all of them
}

rule _home_anir0y_Desktop_malware_analysis_samples_reverse_2 {
   meta:
      description = "samples - file reverse.elf"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-09-06"
      hash1 = "0668c7b76f532225a19a511f1d7c9769759e220d33e61e8b9ba861e0e50a3292"
   strings:
      $s1 = "AYPj)X" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1KB and
      all of them
}

rule _home_anir0y_Desktop_malware_analysis_samples_loki {
   meta:
      description = "samples - file loki.log"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-09-06"
      hash1 = "a6aad4576f711f990103b67a3dc75f508318526a649cf267891fa0481658b730"
   strings:
      $s1 = "20210906T14:49:17Z thm LOKI: Info: MODULE: Results MESSAGE: Please report false positives via https://github.com/Neo23x0/signatu" ascii
      $s2 = "20210906T14:49:17Z thm LOKI: Info: MODULE: Results MESSAGE: Please report false positives via https://github.com/Neo23x0/signatu" ascii
      $s3 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: Processing YARA rules folder /home/anir0y/Desktop/malware-analysis/tool" ascii
      $s4 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: Processing YARA rules folder /home/anir0y/Desktop/malware-analysis/tool" ascii
      $s5 = "20210906T14:49:17Z thm LOKI: Notice: MODULE: Init MESSAGE: Program should be run as 'root' to ensure all access rights to proces" ascii
      $s6 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: False Positive Hashes initialized with 30 hashes" fullword ascii
      $s7 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: Malicious SHA1 Hashes initialized with 7204 hashes" fullword ascii
      $s8 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: Malicious SHA256 Hashes initialized with 23152 hashes" fullword ascii
      $s9 = "20210906T14:49:11Z thm LOKI: Notice: MODULE: Init MESSAGE: Starting Loki Scan VERSION: 0.44.0 SYSTEM: thm TIME: 20210906T14:49:1" ascii
      $s10 = "20210906T14:49:12Z thm LOKI: Info: MODULE: Init MESSAGE: Malicious MD5 Hashes initialized with 19181 hashes" fullword ascii
      $s11 = "20210906T14:49:17Z thm LOKI: Notice: MODULE: Results MESSAGE: Finished LOKI Scan SYSTEM: thm TIME: 20210906T14:49:17Z" fullword ascii
      $s12 = "20210906T14:49:17Z thm LOKI: Info: MODULE: FileScan MESSAGE: Scanning Path /home/anir0y/Desktop/malware-analysis/samples/ ...  " fullword ascii
      $s13 = "20210906T14:49:15Z thm LOKI: Info: MODULE: Init MESSAGE: Initializing all YARA rules at once (composed string of all rule files)" ascii
      $s14 = "20210906T14:49:17Z thm LOKI: Notice: MODULE: Init MESSAGE: Program should be run as 'root' to ensure all access rights to proces" ascii
      $s15 = "20210906T14:49:17Z thm LOKI: Result: MODULE: Results MESSAGE: SYSTEM SEEMS TO BE CLEAN." fullword ascii
      $s16 = "20210906T14:49:11Z thm LOKI: Notice: MODULE: Init MESSAGE: Starting Loki Scan VERSION: 0.44.0 SYSTEM: thm TIME: 20210906T14:49:1" ascii
      $s17 = "s memory and file objects." fullword ascii
      $s18 = "s/loki/signature-base/yara" fullword ascii
      $s19 = "20210906T14:49:17Z thm LOKI: Info: MODULE: Init MESSAGE: Initialized 759 Yara rules" fullword ascii
      $s20 = "20210906T14:49:17Z thm LOKI: Notice: MODULE: Results MESSAGE: Results: 0 alerts, 0 warnings, 2 notices" fullword ascii
   condition:
      uint16(0) == 0x3032 and filesize < 5KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

