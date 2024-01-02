#!/bin/bash

#blacklisted hashes of certificates
wget https://sslbl.abuse.ch/blacklist/sslblacklist.csv

#blacklist of IPs
wget https://sslbl.abuse.ch/blacklist/sslipblacklist.txt

#blacklist of JA3 fingerprints
wget https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv

#IP to ASN -- untested wget
wget https://iptoasn.com/data/ip2asn-v4.tsv.gz
gzip -d ip2asn-v4.tsv.gz

#Top million sites -- untested wget
wget https://downloads.majestic.com/majestic_million.csv

#JA3 to User-agent for OSX and Nix
wget https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv
