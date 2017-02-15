# Large-Scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew

This repository hosts data and code for our research paper 
*Large-Scale Classification of IPv4-IPv6 Siblings with Nonlinear Clock Skew*.

# Brief description 

This code can, based on a set of associated A/AAAA DNS records, conduct TCP timestamp measurements and measure the clock skew of remote hosts. Based on this clock skew, it can discern whether a set of IPv4/IPv6 addresses is hosted on the same machine (siblings) or not (non-siblings). Our code also works on nonlinear clock skew using spline fitting:

<img src="spline.png?raw=true" style="width:100%;">


# How to obtain our dataset

The ground truth host list is included in this repository.
The full ground truth and large scale datasets (including raw measurements) are hosted on our servers due to their size, please send us an [email](mailto:data-request@net.in.tum.de?subject=Access%20to%20large%20scale%20sibling%20data&body=Hi,%0A%0A%20please%20grant%20me%20access%20to%20the%20large%20scale%20sibling%20data%20set.%0A%20My%20affiliation%20is%20CHANGEME%20and%20I%20want%20to%20use%20the%20data%20for%20CHANGEME.%20%0A%0AI%20have%20read%20and%20agree%20to%20the%20Acceptable%20Use%20Policy.%0A%0AThank%20you,%20kind%20regards).

We will provide data sets after registration and agreement to our Acceptable Use Policy (see below).   

# How to use our code

1. Resolve DNS files for A/AAAA records (we used [massdns](https://github.com/blechschmidt/massdns))
2. Parse DNS answers into sibling candidates, using `dns-to-siblingcands.lua`
3. Optional: scan sibling candidates for open ports and TCP options (we used [zmap](https://github.com/zmap/zmap))
4. Optional: parse zmap output and create hitlists for measurement using `zmap-filter-siblings.lua`
5. Optional: If remaining sibling candidates are too many for one run, split them using `siblingcands-split.lua` (chunk size definable, we used 10k)
6. Run the timestamp measurement `measure_ts.py`. It takes IP addresses or sibling candidate lists as input and creates a pcap file with the relevant packets.
7. Now extract the timestamps from the pcap file. For performance reasons, this is done in C++, and requires compilation by typing `make`. Then run `extract_ts` and pipe its output to a .csv file. Confer section Details for a comparison of TS extraction options.
8. Now call `sibling_decision.py`, which takes the sibling/non-sibling decision based on the timestamps.

# How to contribute

We are eager to expand our sibling ground truth, if you host dual-stacked IPv4/IPv6 addresses and are ok with occasional research scans, please kindly submit this data to us! 

Also, code and functionality improvements are highly welcome!

### Authors

[Quirin Scheitle](https://www.net.in.tum.de/en/members/scheitle) ,
[Oliver Gasser](https://www.net.in.tum.de/en/members/gasser) ,
[Minoo Rouhi](https://www.net.in.tum.de/en/members/rouhi)  , and
[Georg Carle](https://www.net.in.tum.de/en/members/carle) 


### Acceptabe Use Policy

1. Please do not further distribute data and take appropriate measures against access by others.
2. You may only access the data to conduct research in the context of Sibling analysis. For further research, please contact us regarding authorization.

We use the gathered data for statistical purposes and might very occasionally send a survey or other requests for feedback.



## Details

### extract_ts

Several options proved unable to process large (15GB) pcap files in reasonable (<15min) time:

* tshark used up 24G of RAM and crashed, terribly slow on smaller files. Internet says it does elaborate flow tracking which we do not need
* scapy was terribly slow, a pure read loop would take ~30 minutes for just 1GB
* pyshark was faster, ~5 minutes for 1GB
* Ridiculous: tcpdump to text, then parsing from python takes roughly 60 seconds per file. However, the regex is complex and error-prone (multi-line!), and producing large unstructured text files from a nice binary format hurts
* The C++ solution parses 1GB in 50 seconds :)
