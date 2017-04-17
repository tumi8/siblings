# How to obtain siblings

1. Resolve DNS files for A/AAAA records (we used massdns)
2. Parse DNS answers into sibling candidates, using `dns-to-siblingcands.lua`
3. Optional: scan sibling candidates for open ports and TCP options (we used zmap)
4. Optional: parse zmap output and create hitlists for measurement using `zmap-filter-siblings.lua`
5. Optional: If remaining sibling candidates are too many for one run, split them using `siblingcands-split.lua` (junk size definable, we used 10k)
6. Run the Timestamp measurement `measure_ts.py`. It takes IP addresses or sibling candidate lists as input and creates a pcap file with the relevant packets.
7. Now extract the timestamps from the pcap file. For performance reasons, this is done in C++, and requires compilation by typing `make`. Then run `extract_ts` and pipe its output to a .csv file.
8. Now call `sibling_decision.py`, which takes the sibling/non-sibling decision based on the timestamps.


## Details

### extract_ts

Several options proved unable to process large (15GB) pcap files in reasonable (<15min) time:
 * tshark used up 24G of RAM and crashed, terribly slow on smaller files. Internet says it does elaborate flow tracking which we do not need
 * scapy was terrible slow, a pure read loop would take ~30 minutes for just 1GB
 * pyshark was faster, ~5 minutes for 1GB
 * Ridiculous: tcpdump to text, then parsing from python takes roughly 60 seconds per file. However, the regex is complex and error-prone (multi-line!), and producing large unstructured text files from a nice binary format hurts
 * The C++ solution parses 1GB in 50 seconds :)
