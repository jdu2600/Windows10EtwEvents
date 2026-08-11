# Windows 10 ETW Events
Events from all manifest-based and mof-based ETW providers across Windows 10 versions

| Version | Events | Manifest Providers | MOF Providers | Unknown Providers |
|---    |---        |---	|---	|---	|
| 1511  | 43,319    | 811	| 195   | 24    |
| 1607  | 45,569    | 830	| 193   | 23    |
| 1703  | 46,532    | 842	| 194   | 31    |
| 1709  | 47,687    | 854	| 193   | 28    |
| 1803  | 48,226    | 855	| 192   | 29    |
| 1809  | 49,080    | 863	| 190   | 25    |
| 1903  | 49,734    | 867	| 187   | 24    |
| 1909  | 49,773    | 868	| 187   | 24    |
| 2004  | 50,391    | 871	| 187   | 25    |
| 2009  | 50,399    | 872	| 187   | 25    |
| 21H1  | 50,505    | 871	| 187   | 28    |
| 21H2  | 51,696    | 876	| 187   | 25    |
| 22H2  | 52,807    | 884	| 186   | 18    |
| 23H2  | 53,144    | 893	| 186   | 18    |
| 24H2  | 54,295    | 889	| 182   | 24    |
| 25H2  | 54,874    | 894	| 182   | 26    |
| 26H1  | 55,551    | 898	| 182   | 26    |

Useful references
-----------------

* https://github.com/jdu2600/API-To-ETW
* https://github.com/jdu2600/ETW-PPL-Tester

Microsoft
 * https://learn.microsoft.com/en-us/windows/win32/etw/event-metadata-overview
 * https://github.com/microsoft/perfview
 * https://github.com/microsoft/krabsetw

Nedim Šabić [@arch_rabbit](https://twitter.com/arch_rabbit)
 * https://github.com/rabbitstack/fibratus

 Origin [@originhq](https://twitter.com/originhq)
 * https://www.originhq.com/research/securitytrace-etw-ppl
 * https://www.originhq.com/Closing%20the%20Execution%20Gap.pdf

Philipp Schmied [@CaptnBanana](https://twitter.com/CaptnBanana), Sebastian Feldmann [@thefLinkk](https://twitter.com/thefLinkk) and Dominik Phillips
 * https://github.com/threathunters-io/kassandra_x33fcon_2026
 * [Building an ETW Based Sysmon Replacement From Scratch](https://www.x33fcon.com/slides/x33fcon24_-_Sebastian_Feldmann_and_Philipp_Schmied_-_Busting_Redteam_Trends_with_Style_-_Lessons_Learned_from_Building_an_ETW_based_Sysmon_Replacement_from_Scratch.pdf), x33fcon 2024

Elastic Security Labs [@elasticseclabs](https://twitter.com/elasticseclabs)
* https://www.elastic.co/security-labs/kernel-etw-best-etw
* https://www.elastic.co/security-labs/doubling-down-etw-callstacks

Matt Graeber [@mattifestation](https://twitter.com/mattifestation)
 * https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
 * https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7
 * [How do I detect technique X in Windows?](https://drive.google.com/file/d/19AhMG0ZCOt0IVsPZgn4JalkdcUOGq4DK/view), DerbyCon 2019
 * https://github.com/mattifestation/WindowsEventLogMetadata
 * https://gist.github.com/mattifestation/04e8299d8bc97ef825affe733310f7bd - NiftyETWProviders.json
 * https://gist.github.com/mattifestation/edbac1614694886c8ef4583149f53658 - TLGMetadataParser.psm1

Nasreddine Bencherchali [@nasbench](https://twitter.com/nas_bench)
 * https://github.com/nasbench/ETW-Resources#blogs--research-httpsnasbenchmediumcom
 * https://github.com/nasbench/ETW-Resources - XML manifests
 
Pat H [@pathtofile](https://twitter.com/pathtofile)
 * https://blog.tofile.dev/categories/#etw
 * https://github.com/pathtofile/Sealighter
 * https://github.com/pathtofile/SealighterTI

Zac Brown [@zacbrown](https://twitter.com/zacbrown)
 * https://zacbrown.org/2017/04/11/hidden-treasure-intrusion-detection-with-etw-part-1
 * https://zacbrown.org/2017/05/9/hidden-treasure-intrusion-detection-with-etw-part-2
 * https://github.com/zacbrown/hiddentreasure-etw-demo

Ruben Boonen [@FuzzySec](https://twitter.com/FuzzySec)
 * https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html
 * https://github.com/fireeye/SilkETW

Pavel Yosifovich [@zodiacon](https://twitter.com/zodiacon)
 * https://github.com/zodiacon/EtwExplorer
 * https://github.com/zodiacon/ProcMonX

Elias Bachaalany [@0xeb](https://twitter.com/0xeb)
 * https://github.com/lallousx86/WinTools/tree/master/WEPExplorer

 Bruce Dawson
 * https://randomascii.wordpress.com/2015/09/24/etw-central/

Geoff Chappell
 * https://www.geoffchappell.com/studies/windows/win32/advapi32/api/etw/
 * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntwmi/perfinfo_groupmask.htm
 * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntwmi/wmi_trace_packet/hookid.htm
