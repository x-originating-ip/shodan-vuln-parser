#!/usr/bin/env python3

import os
import re
import sys
import json
import gzip
import csv
import datetime
import shodan

'''
Parses shodan files and pulls out CVE details by host
"IP CVE Verified CVSS Summary References"
And writes to new csv file

0. pip install shodan
1. Assuming shodan data files have been obtained
2. python3 parse-shodan-cve-data.py <directory>
'''

csv_out = []

def parse_shodan_file(fname):
    if fname.split(".")[-1] == "gz":
        data = gzip.open(fname, 'r').read().decode('utf-8').strip()
        data = data.split('\n')
    else:
        with open(fname,'r') as f:
            data = [e for e in f if e.strip()]

    for e in data:
        e = json.loads(e)
        ip = e['ip_str']
        ssl = e["ssl"]["cert"]["subject"]["CN"]
        if 'vulns' in e and e['vulns'] is not None:
            vulns = e['vulns']
            ip = e['ip_str']
            ssl = e["ssl"]["cert"]["subject"]["CN"]
            for v in vulns:
                cve = v
                verified = vulns[v]['verified']
                cvss = vulns[v]['cvss']
                summary = vulns[v]['summary']
                ref = vulns[v]['references']
                references = ", ".join(ref)
                '''
                print("\nIP: {},".format(ip))
                print("SSL Subject CN: {},".format(ssl1)
                print("CVE: {},".format(v))
                print("Verified: {},".format(verified))
                print("CVSS: {},".format(cvss))
                print("Summary: {},".format(summary))
                print("References: {}".format(references))
                '''
                csv_out.append([ip,",",ssl1,",",cve,",",verified,",",cvss,",",summary,",",references])

def write_csv():
    fname = "cves-{}.csv".format(datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f"))
    with open(fname, 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter='\t')

        writer.writerow(["IP\t,SSL Subject CN\t,CVE\t,Verified\t,CVSS\t,Summary\,tReferences"])
        for line in csv_out:
            line = "\t".join([str(e) for e in line])
            writer.writerow([line])

    print("Wrote {} results to {}".format(len(csv_out), fname))

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <directory with shodan results files>".format(sys.argv[0]))
        exit(1)

    directory = sys.argv[1]
    for root, dirs, files in os.walk(directory):
        for name in files:
           if re.findall("json|gz", name.split(".")[-1]):
                p = os.path.join(root,name)
                parse_shodan_file(p)
        break

    if len(csv_out) > 0:
        write_csv()
    else:
        print("No CVEs in this directory")

if __name__ == "__main__":
    main()
