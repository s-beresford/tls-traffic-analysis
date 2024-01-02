Ensure you populate the datasets with the most up to date versions. This can be done by running "update_blacklists.sh." Note that this pulls from various third party websites.

This program requires Zeek, unless Zeek logs are already available in the proper format.

It also depends on freq.py and freqtable2018.freq from Mark Baggett at https://github.com/MarkBaggett/freq


If you don't already have Zeek log files (sudo needs permissions to run Zeek):

sudo python3 main.py pcap/example.pcap

If you already have Zeek log files in the zeek folder:

sudo python3 main.py


Output files go to the "output" directory.
A good place to start is the weird.csv file.





Here is what your directory structure should look like:

datasets
---->update_blacklists.sh
output
---->output files for analysis
pcap
---->pcap files to analyze
zeek
---->zeek files
freq.py
freqtable2018.freq
main.py
