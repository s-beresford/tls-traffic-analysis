import ipaddress
import json
import subprocess
import sys
from datetime import datetime
from freq import *
import csv



def run_zeek(pcap):
    """
    This function launches a subprocess to run Zeek on the provided pcap file.
    """
    print("Running Zeek, this may take a little bit")
    subprocess.run(["/opt/zeek/bin/zeek", "-C", "-r", pcap, "LogAscii::use_json=T", "X509::hash_function=sha1_hash", "Log::default_logdir=zeek/", "local"], stderr=subprocess.DEVNULL)
    return

def load_json(contents):
    """
    This function loads the contents of a Zeek log file into the Python JSON format.
    Returns: A list of dictionaries containing the Zeek log file contents.
    """
    json_items = []
    for line in contents:
        json_items += [json.loads(line)]
    return json_items

def ja3_user_agent(ja3_list):
    """
    This function finds associated user agents given a dictionary of UID: JA3 pairs.
    Currently the file used for these associations only supports certain nix user agents.
    Returns: A list of UIDs and User Agents.
    """
    file = open("datasets/osx-nix-ja3.csv", "r")
    user_agents = {}
    results = []
    for i in range(4):
        file.readline()
    for line in file:
        user_agents_line = line.split(',')
        user_agents[user_agents_line[0]] = user_agents_line[1]

    user_agent_ja3 = list(user_agents.keys())

    for item in ja3_list.values():
        if item in user_agent_ja3:
            for uid in list(ja3_list.keys()):
                if ja3_list[uid] == item:
                    results += [uid, user_agents[item]]

    file.close()
    return results

def check_ja3(items):
    """
    This function identifies all JA3 hashes from the log file and compares them
    against a blacklist. This function also calls the user agent function.
    Returns:
    results: A list of the results, consisting of the UID, JA3, and description.
    user_agents: The result of the ja3_user_agent function.
    unique_blacklist: A list of just blacklisted JA3 hashes and descriptions.
    """
    results = []
    ja3_list = {}
    unique_blacklist = []

    for line in items:
        ja3_list[line["uid"]] = line["ja3"]
    user_agents = ja3_user_agent(ja3_list)

    file = open("datasets/ja3_fingerprints.csv", "r")
    ja3_database = {}
    for line in file:
        if line[0] != "#":
            ja3_line = line.split(',')
            ja3_database[ja3_line[0]] = ja3_line[3]

    database_hashes = list(ja3_database.keys())
    for hash in database_hashes:
        if hash in list(ja3_list.values()):
            for uid in list(ja3_list.keys()):
                if ja3_list[uid] == hash:
                    results += [[uid, hash, ja3_database[hash]]]
            unique_blacklist += [[hash, ja3_database[hash]]]

    file.close()
    return results, user_agents, unique_blacklist

def binary_search(search_data, value):
    """
    This function implements a binary search used to find the appropriate ASN association.
    Returns: The associated ASN.
    """
    key_list = list(search_data.keys())
    start = 0
    end = len(key_list) - 1
    check = end // 2
    while start <= end:
        if key_list[check] == value:
            return search_data[key_list[check]]
        if key_list[check] < value:
            if key_list[check + 1] > value:
                return search_data[key_list[check]]
            start = check + 1
        if key_list[check] > value:
            end = check - 1
        check = (start + end) // 2
    return -1

def ip_asn(items, skip):
    """
    This function generates an IP list from the SSL connections and
    correlates the IPs to their associated ASN.
    Returns:
    ip_list: A list of all SSL IPs.
    results: A list of [IP, ASN] pairs.
    """
    results = []
    ip_list = []
    for line in items:
        ip_list += [line["id.orig_h"]]
        ip_list += [line["id.resp_h"]]
    ip_list = list(dict.fromkeys(ip_list))

    if skip == 0:
        file = open("datasets/ip2asn-v4.tsv", "r")
        data = file.readlines()
        full_data = {}
        for item in data:
            line = item.split('\t')
            first_ip = int(ipaddress.ip_address(line[0]))
            full_data[first_ip] = line

        for ip in ip_list:
            ip_int = int(ipaddress.ip_address(ip))
            value = binary_search(full_data, ip_int)
            results += [[ip, value[4]]]

        file.close()
    return ip_list, results

def check_ips(ip_list):
    """
    This function compares an IP list against a blacklist.
    Returns: A list of all blacklisted IPs found.
    """
    results = []
    blacklist = []
    file = open("datasets/sslipblacklist.txt", "r")
    for line in file:
        if line[0] != "#":
            blacklist += [line.split('\n')[0]]
    
    blacklist_set = set(blacklist)
    
    for item in ip_list:
        if item in blacklist_set:
            results += [item]

    file.close()

    return results

def pull_server_names(ssl_log, x509_log):
    """
    This function identifies all server names in the SSL log. If there is no server name,
    then it checks the associated certificate and pulls the name from the certificate.
    Returns:
    server_list: A list of all found server names in the format: [UID, Name, Certificate fingerprint].
    no_server_list: Same as server_list, but only contains names that were not in the SSL log.
    """
    server_list = []
    no_server_list = []
    for line in ssl_log:
        try:
            server_list += [[line["uid"], line["server_name"], "fromSSL"]]
        except:
            try:
                for fingerprint in line["cert_chain_fps"]:
                    for cert_line in x509_log:
                        try:
                            if fingerprint == cert_line["fingerprint"]:
                                name = cert_line["certificate.subject"].split('CN=')[1]
                                if ',' in name:
                                    name = name.split(',')[0]
                                if '*' in name:
                                    name = name.split('*.')[1]
                                no_server_list += [[line["uid"], name, fingerprint]]
                                server_list += [[line["uid"], name, fingerprint]]
                        except:
                            continue
            except:
                continue

    return server_list, no_server_list

def check_majestic_million(server_names):
    """
    This function takes a list of server names and checks them against the Majestic Million
    data file. Any servers not on the Majestic Million will be flagged.
    Returns: A list of all server names not on the Majestic Million in the format:
    [UID, server name, certificate fingerprint].
    """
    results = []

    file = open("datasets/majestic_million.csv", "r")

    data = file.readlines()
    domains = []
    for item in data:
        line = item.split(',')
        first_3 = line[2].split('.')[-3:]
        domains += ['.'.join(first_3)]
    del(data)
    file.close()

    for item in server_names:
        first_3 = item[1].split('.')[-3:]
        if first_3[-1] in ["com", "org", "gov", "net"]:
            first_3 = first_3[-2:]
        domain = '.'.join(first_3)
        if domain not in domains:
            results += [[item[0], domain, item[2]]]

    return results

def check_entropy(data_list):
    """
    This function uses freq.py to calculate the entropy of the server names from a provided list.
    Returns: A list of the server names and their probability (lower means higher entropy).
    """
    fc = FreqCounter()
    fc.load("freqtable2018.freq")
    results = []
    for item in data_list:
        prob1, prob2 = fc.probability(item[1])
        prob = (prob1 + prob2)/2
        if prob < 4:
            item += [str(prob)]
            results += [item]

    return results

def check_cert_validation(ssl_log):
    """
    This function identifies all certificates that are not properly validated.
    Returns:
    cert_validations: A list of all validation statuses, in the format: [UID. status, server name].
    weird_validations: A list of all certificates that are not properly validated, same format as above.
    """
    cert_validations = []
    weird_validations = []
    for line in ssl_log:
        try:
            status = line["validation_status"]
            cert_validations += [[line["uid"], status, line["server_name"]]]
            if status != "ok":
                weird_validations += [[line["uid"], status, line["server_name"]]]
        except:
            try:
                cert_validations += [[line["uid"], status, "No server name"]]
                if status != "ok":
                    weird_validations += [[line["uid"], status, "No server name"]]
            except:
                continue
    return cert_validations, weird_validations

def check_cert_details(x509_items, ssl_log):
    """
    This function pulls all certificate subject and issuer details. It also calculated the entropy of each value.
    Returns:
    subject_list: A list of all subject details of the format [fingerprint, [field, value, entropy]x7, [[UID, server name]...]]
    issuer_list: Same as above, but for issuer details.
    """
    cert_subject = {}
    cert_issuer = {}
    subject_list = []
    issuer_list = []
    for line in x509_items:
        try:
            cert_subject[line["certificate.subject"]] = line["fingerprint"]
            cert_issuer[line["certificate.issuer"]] = line["fingerprint"]
        except:
            continue

    fc = FreqCounter()
    fc.load("freqtable2018.freq")
    for subject in cert_subject.keys():
        uids = fingerprint_to_uid(cert_subject[subject], ssl_log)
        subject_info = [cert_subject[subject]]
        split_subject = subject.split(',')
        for i in range(len(split_subject)):
            split_subject[i] = split_subject[i].split('=')
            prob1, prob2 = fc.probability(split_subject[i][-1])
            split_subject[i] += [(prob1 + prob2)/2]
            while len(split_subject[i]) < 3:
                split_subject[i].insert(0, "Uknown")
        while len(split_subject) < 7:
            split_subject += [["","",99]]
        subject_info += split_subject
        subject_info += [uids]
        subject_list += [subject_info]

    for issuer in cert_issuer.keys():
        uids = fingerprint_to_uid(cert_issuer[issuer], ssl_log)
        issuer_info = [cert_issuer[issuer]]
        split_issuer = issuer.split(',')
        for i in range(len(split_issuer)):
            split_issuer[i] = split_issuer[i].split('=')
            prob1, prob2 = fc.probability(split_issuer[i][-1])
            split_issuer[i] += [(prob1 + prob2)/2]
            while len(split_issuer[i]) < 3:
                split_issuer[i].insert(0, "Uknown")
        while len(split_issuer) < 7:
            split_issuer += [["","",99]]
        issuer_info += split_issuer
        issuer_info += [uids]
        issuer_list += [issuer_info]
    
    return subject_list, issuer_list

def check_weird_cert(details_list):
    """
    This function checks subject and issuer detail entropy and flags on those with high entropy.
    Returns: A list of all of the subject or issuer details that were flagged.
    """
    results = []

    for item in details_list:
        length = len(item)
        for i in range(length):
            if i == 0 or i == length - 1:
                continue
            if (item[i][2] < 4 and len(item[i][1]) > 3):
                results += [item]

    return results

def check_cert_hash(x509_items, ssl_log):
    """
    This function checks each certificate fingerprint against a blacklist file.
    Returns: A list of all flagged certificates in the format: [fingerprint, description, UID].
    """
    blacklist = {}
    results = []
    fingerprints = []
    for line in x509_items:
        try:
            fingerprints += [line["fingerprint"]]
        except:
            continue

    file = open("datasets/sslblacklist.csv", "r")
    
    for line in file:
        if line[0] != "#":
            data = line.split(',')
            blacklist[data[1]] = data[2].split('\n')[0]
    
    blacklist_set = set(blacklist.keys())
    
    for item in fingerprints:
        if item in blacklist_set:
            uids = fingerprint_to_uid(item, ssl_log)
            results += [[item, blacklist[item], uids]]

    file.close()
    return results

def check_ports_protocols(ssl_log):
    """
    This function gathers all the ports and next protocol fields used for SSL connections.
    Returns: A list of the format: [UID, port, protocol, server name]
    """
    ports_protocols = []
    for line in ssl_log:
        if "next_protocol" in line.keys():
            try:
                ports_protocols += [[line["uid"], line["id.resp_p"], line["next_protocol"], line["server_name"]]]
            except:
                try:
                    ports_protocols += [[line["uid"], line["id.resp_p"], line["next_protocol"], "No Server Name"]]
                except:
                    continue
        else:
            try:
                ports_protocols += [[line["uid"], line["id.resp_p"], "Protocol not listed", line["server_name"]]]
            except:
                try:
                    ports_protocols += [[line["uid"], line["id.resp_p"], "Protocol not listed", "No Server Name"]]
                except:
                    continue

    return ports_protocols

def check_serial_length(x509_log, ssl_log):
    """
    This function checks the length of all certificate serial numbers. If they are below the length of 8, they are flagged.
    Returns: A list of all flagged certificates, in the format: [fingerprint, length, UID]
    """
    serials = []
    for line in x509_log:
        try:
            length = len(line["certificate.serial"])
            if length < 8:
                uids = fingerprint_to_uid(line["fingerprint"], ssl_log)
                serials += [[line["fingerprint"], length, uids]]
        except:
            continue
    
    return serials

def check_cert_dates(x509_log, ssl_log):
    """
    This function pulls the start and end dates from each certificate and calculates the difference.
    It flags on certificates with durations more than 398 days.
    Returns:
    dates: A list of the certificate dates information, of the format: [fingerprint, first date, last date, duration, UIDs]
    weird_dates: Same information as above for only flagged certificates.
    """
    dates = []
    weird_dates = []
    for line in x509_log:
        first_date = ""
        last_date = ""
        fingerprint = ""
        try:
            first_date = datetime.fromtimestamp(int(float(line["certificate.not_valid_before"])))
            last_date = datetime.fromtimestamp(int(float(line["certificate.not_valid_after"])))
            date_length = last_date - first_date
            fingerprint = line["fingerprint"]
        except:
            continue
        uids = fingerprint_to_uid(fingerprint, ssl_log)
        dates += [[fingerprint, str(first_date), str(last_date), date_length.days, uids]]
        if date_length.days > 398:
            weird_dates += [[fingerprint, str(first_date), str(last_date), date_length.days, uids]]

    return dates, weird_dates

def pull_connections(ssl_log):
    """
    This function pulls the conn.log information for only the relevant SSL connections.
    Returns: A list of all SSL connection items.
    """
    uids = []
    for line in ssl_log:
        try:
            uids += [line["uid"]]
        except:
            continue

    uid_set = set(uids)
    
    file = open("zeek/conn.log", "r")
    conn_contents = file.readlines()
    conn_items = load_json(conn_contents)
    del(conn_contents)
    file.close()
    
    ssl_conn = []
    for i in range(len(conn_items)):
        if conn_items[i]["uid"] in uid_set:
            conn_items[i]["ts"] = str(datetime.fromtimestamp(int(float(conn_items[i]["ts"]))))
            ssl_conn += [conn_items[i]]
    return ssl_conn

def check_connections(connections):
    """
    This function checks SSL connections for long durations, large outbound data,
    and high upload to download ratios.
    Returns:
    duration: A list of all long connections in the format [UID, duration]
    data_size: A list of all large outbound connections in the format [UID, bytes]
    ratio: A list of all large upload to download ratios in the format [UID, ratio]
    """
    duration = []
    data_size = []
    ratio = []
    for item in connections:
        if float(item["duration"]) > 3600:
            duration += [[item["uid"], float(item["duration"])/60]]
        if int(item["orig_ip_bytes"]) > 10000000:
            data_size += [[item["uid"], item["orig_ip_bytes"]]]
        ratio_calc = int(item["orig_ip_bytes"])/int(item["resp_ip_bytes"])
        if ratio_calc > 2:
            ratio += [[item["uid"], str(ratio_calc)]]

    return duration, data_size, ratio

def fingerprint_to_uid(fingerprint, ssl_log):
    """
    This function takes certificate fingerprints and finds the associated UID and server name.
    Returns: A list of the format [UID, server name].
    """
    uids = []
    for line in ssl_log:
        try:
            if fingerprint in line["cert_chain_fps"]:
                try:
                    uids += [[line["uid"], line["server_name"]]]
                except:
                    uids += [[line["uid"], "No server name"]]
        except:
            continue
    return uids

def write_to_csv(writer, data, note, categories):
    """
    This function writes data to a csv file.
    """
    writer.writerow([note])
    writer.writerow(categories)
    for item in data:
        writer.writerow(item)
    writer.writerow("")

    return

def write_to_weird(ja3_blacklist, ip_blacklist, no_server_names, uncommon_servers, server_entropy, 
                   weird_validations, weird_subject, weird_issuer, blacklist_certs, serial_length, 
                   weird_dates, long_duration, large_data, weird_ratio):
    """
    This function writes all of the flagged data to a csv file titled "weird.csv".
    """
    
    file = open("output/weird.csv", "w")
    writer = csv.writer(file)

    write_to_csv(writer, ja3_blacklist, "JA3 Blacklist", ["UID", "JA3", "Details"])
    write_to_csv(writer, ip_blacklist, "IP Blacklist", ["IP Address"])
    write_to_csv(writer, no_server_names, "No Server Name", ["UID", "Name from Certificate", "Certificate Fingerprint"])
    write_to_csv(writer, uncommon_servers, "Uncommon Servers", ["UID", "Server Name", "Certificate Fingerprint"])
    write_to_csv(writer, server_entropy, "High Entropy Servers", ["UID", "Server Name", "Certificate Fingerprint", "Probability"])
    write_to_csv(writer, weird_validations, "Certificate Validation Issue", ["UID", "Description", "Server Name"])
    write_to_csv(writer, weird_subject, "Weird Subject Details", ["Fingerprint", "Subject Details", "", "", "", "", "", "", "UIDs and Server Names"])
    write_to_csv(writer, weird_issuer, "Weird Issuer Details", ["Fingerprint", "Issuer Details", "", "", "", "", "", "", "UIDs and Server Names"])
    write_to_csv(writer, blacklist_certs, "Blacklisted Certificates", ["Fingerprint", "Description", "UIDs and Server Names"])
    write_to_csv(writer, serial_length, "Small Cert Serial Length", ["Fingerprint", "Length", "UIDs and Server Names"])
    write_to_csv(writer, weird_dates, "Suspicious Cert Expiration Date", ["Fingerprint", "Starting Date", "End Date", "Valid Time in Days", "UIDs and Server Names"])
    write_to_csv(writer, long_duration, "Long Connection", ["UID", "Duration in Minutes"])
    write_to_csv(writer, large_data, "Large Outbound Data", ["UID", "Data Size in Bytes"])
    write_to_csv(writer, weird_ratio, "High Upload to Download Ratio", ["UID", "Ratio"])
    
    file.close()

    return

def write_to_cert_details(subject_details, issuer_details):
    """
    This file writes all certificate details to a file title "certificate_details.csv".
    """
    file = open("output/certificate_details.csv", "w")
    writer = csv.writer(file)

    write_to_csv(writer, subject_details, "Certificate Subject", ["Fingerprint", "Subject Details", "", "", "", "", "", "", "UIDs and Server Names"])
    write_to_csv(writer, issuer_details, "Certificate Issuer", ["Fingerprint", "Issuer Details", "", "", "", "", "", "", "UIDs and Server Names"])

    return

def write_to_server_names(server_names):
    """
    This function counts the instances of all server names and writes them to a file.
    """
    file = open("output/server_names.csv", "w")
    writer = csv.writer(file)

    unique_names = {}
    names = []
    for item in server_names:
        if item[1] not in names:
            unique_names[item[1]] = [1, [item[0]], [item[2]]]
            names += [item[1]]
            #print(unique_names)
        else:
            unique_names[item[1]][0] += 1
            unique_names[item[1]][1] += [item[0]]
            unique_names[item[1]][2] += [item[2]]
            #print(unique_names)

    server_list = []
    for item in unique_names.keys():
        server_item = unique_names[item]
        server_item.insert(0, item)
        server_list += [server_item]

    server_list.sort(key=lambda server_list: server_list[1])

    write_to_csv(writer, server_list, "Server Names", ["Server Name", "Count", "UID", "Fingerprint"])

    return

def write_to_ports_protocols(ports_protocols):
    """
    This function writes all ports and protocols to a file.
    """
    file = open("output/ports_protocols.csv", "w")
    writer = csv.writer(file)

    write_to_csv(writer, ports_protocols, "Ports and Protocols", ["UID", "Port", "Next Protocol", "Server"])

    return

def write_to_asn(asn_list):
    """
    This function writes all IP to ASN correlations to a file.
    """
    file = open("output/asn.csv", "w")
    writer = csv.writer(file)

    write_to_csv(writer, asn_list, "ASNs", ["IP Address", "ASN"])

    return

def write_to_connections(conn_items):
    """
    This function writes all SSL connection data to a file.
    """
    file = open("output/ssl_connections.csv", "w")
    writer = csv.writer(file)

    writer.writerow(["Connection Data For SSL Connections"])
    counter = 0
    for item in conn_items:
        if counter == 0:
            writer.writerow(item.keys())
            counter = 1
        writer.writerow(item.values())

    return

def write_to_user_agent(user_agents):
    """
    This function writes all found user agents to a file.
    """

    file = open("output/user_agents.csv", "w")
    writer = csv.writer(file)

    write_to_csv(writer, user_agents, "User Agents", ["UID", "User Agent"])

    return


def main():
    argument_length = len(sys.argv)
    fast = 0
    if argument_length > 3:
        print("Invalid arguments")
        print("Example usage to include running zeek: python3 main.py pcap/example.pcap")
        print("Example usage to skip running zeek): python3 main.py")
        print("Example usage to skip finding ASNs (faster)): python3 main.py --fast")
        exit()
    if argument_length == 2:
        if "pcap" in sys.argv[1]:
            try:
                run_zeek(sys.argv[1])
                print("Zeek successfully ran")
            except:
                print("Zeek failed to run on the provided file. Ensure you provided a proper pcap file in the pcap folder and are using sudo")
                exit()
        elif sys.argv[1] == "--fast":
            fast = 1
        else:
            print("Invalid arguments")
            print("Example usage to include running zeek: python3 main.py pcap/example.pcap")
            print("Example usage to skip running zeek): python3 main.py")
            print("Example usage to skip finding ASNs (faster)): python3 main.py --fast")
            exit()
    if argument_length == 3:
        if "pcap" in sys.argv[1] and sys.argv[2] == "--fast":
            try:
                run_zeek(sys.argv[1])
                print("Zeek successfully ran")
                fast = 1
            except:
                print("Zeek failed to run on the provided file. Ensure you provided a proper pcap file in the pcap folder and are using sudo")
                exit()
        else:
            print("Invalid arguments")
            print("Example usage to include running zeek: python3 main.py pcap/example.pcap")
            print("Example usage to skip running zeek): python3 main.py")
            print("Example usage to skip finding ASNs (faster)): python3 main.py --fast")
            exit()
    try:
        ssl_file = open("zeek/ssl.log", "r")
        ssl_contents = ssl_file.readlines()
        ssl_file.close()
        x509_file = open("zeek/x509.log", "r")
        x509_contents = x509_file.readlines()
        x509_file.close()
    except:
        print("Failed to open zeek files ssl.log and x509.log, run zeek first by specifying a pcap file")

    ssl_items = load_json(ssl_contents)
    x509_items = load_json(x509_contents)
    del(ssl_contents)
    del(x509_contents)
    print("Checking JA3 hashes...")
    ja3_blacklist, user_agents, unique_ja3 = check_ja3(ssl_items)
    print("\nCorrelating ASNs...")
    ip_list, asn_list = ip_asn(ssl_items, fast)
    print("\nChecking IPs...")
    ip_blacklist = check_ips(ip_list)
    print("\nChecking Server Names...")
    server_names, no_server_names = pull_server_names(ssl_items, x509_items)
    uncommon_servers = check_majestic_million(server_names)
    server_entropy = check_entropy(server_names)
    print("\nChecking certificate details:")
    validations, weird_validations = check_cert_validation(ssl_items)
    subject_details, issuer_details = check_cert_details(x509_items, ssl_items)
    weird_subject = check_weird_cert(subject_details)
    weird_issuer = check_weird_cert(issuer_details)
    blacklist_certs = check_cert_hash(x509_items, ssl_items)
    serial_length = check_serial_length(x509_items, ssl_items)
    cert_dates, weird_dates = check_cert_dates(x509_items, ssl_items)
    print("\nChecking connections:")
    ports_protocols = check_ports_protocols(ssl_items)
    conn_items = pull_connections(ssl_items)
    long_duration, large_data, weird_ratio = check_connections(conn_items)
    write_to_weird(ja3_blacklist, ip_blacklist, no_server_names, uncommon_servers, server_entropy, 
                   weird_validations, weird_subject, weird_issuer, blacklist_certs, serial_length, 
                   weird_dates, long_duration, large_data, weird_ratio)
    write_to_cert_details(subject_details, issuer_details)
    write_to_server_names(server_names)
    write_to_ports_protocols(ports_protocols)
    write_to_asn(asn_list)
    write_to_connections(conn_items)
    write_to_user_agent(user_agents)
    print("Complete")
    exit()

if __name__ == '__main__':
    main()