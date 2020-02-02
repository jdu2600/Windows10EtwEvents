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

Want the data in a different format?
------------------------------------
Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)
 * https://github.com/hunters-forge/OSSEM/tree/master/data_dictionaries/windows/etw/json - JSON
 * https://github.com/hunters-forge/OSSEM/tree/yaml/data_dictionaries/yaml/windows - YAML

Useful references
-----------------
Microsoft
 * https://docs.microsoft.com/en-us/windows/win32/etw/event-metadata-overview
 * https://github.com/microsoft/perfview
 * https://github.com/microsoft/krabsetw

Matt Graeber [@mattifestation](https://twitter.com/mattifestation)
 * https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
 * https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7
 * [How do I detect technique X in Windows?](https://drive.google.com/file/d/19AhMG0ZCOt0IVsPZgn4JalkdcUOGq4DK/view), DerbyCon 2019
 * https://github.com/mattifestation/WindowsEventLogMetadata
 * https://gist.github.com/mattifestation/04e8299d8bc97ef825affe733310f7bd - NiftyETWProviders.json
 * https://gist.github.com/mattifestation/edbac1614694886c8ef4583149f53658 - TLGMetadataParser.psm1
 
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