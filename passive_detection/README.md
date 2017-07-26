## Description
This is our tool for IP sibling identification from passive traffic measurements.<br>
In our evaluation, we achieved results ranging from 0.9535 to 0.9867 for the Matthews Correlation Coefficient, although having only very few packets per host (2-6).

## Files
- candidate\_identification.cpp		--> creates possible sibling candidates from connections within the last 30 seconds
- candidate\_decision.cpp			--> gets candidate pairs from identification instance
					   makes final decision based on timestamps and TCP options
- sibling\_tool.cpp			--> main(), also pcap__loop and the main packet handler
- sibling\_tool.h				--> includes, header file
- ring\_buffer.cpp				--> buffer that is used to store important information for each packet information is mapped to host IP
					   
## Usage

make<br>
./sibling\_tool -i eth0<br>
./sibling\_tool -f file.pcap

*Output:*<br>
stdout, or option "-n" to print negative results to file, "-r" to print positive results to file.
