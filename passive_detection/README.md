## Description
This is our tool for IP sibling identification from passive traffic measurements.  

In our evaluation, we achieved results ranging from 0.9535 to 0.9867 for the Matthews Correlation Coefficient, although having only very few packets per host (2-6).

A full description of the tools, its capabilities, the testing approach and evaluation results can be found in Alexander's [Bachelor's Thesis](https://www.net.in.tum.de/fileadmin/bibtex/publications/theses/2017-BSc-Schulz.pdf)

## Files
- candidate\_identification.cpp		--> creates possible sibling candidates from connections within the last 30 seconds
- candidate\_decision.cpp			--> gets candidate pairs from identification instance
					   makes final decision based on timestamps and TCP options
- sibling\_tool.cpp			--> main(), also pcap__loop and the main packet handler
- sibling\_tool.h				--> includes, header file
- ring\_buffer.cpp				--> buffer that is used to store important information for each packet information is mapped to host IP
					   
## Usage

```
make  
./sibling_tool -i eth0
./sibling_tool -f file.pcap
```

*Output:*  
stdout, or option "-n" to print negative results to file, "-r" to print positive results to file.
