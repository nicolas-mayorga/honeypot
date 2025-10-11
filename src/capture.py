import subprocess
import json
import requests
import time
import os

def start_tcpdump(port, interface = 'eth0', output_file = 'pcap_logs/honeypot.pcap'):
	command = ['tcpdump', '-i', interface, '-s', '0', '-nn', 'port ' + str(port), '-w', output_file]
	
	return subprocess.Popen(command)

def pcap_to_txt(path_to_pcap, verbose, output_file):
	if verbose == 1:
		command = ["tshark", "-r", path_to_pcap, "-V"]
	else: 
		command = ["tshark", "-r", path_to_pcap]
		
	return subprocess.Popen(command, stdout = output_file)


def flatten_packet(pkt):
    """
    Extracts key fields from a tshark packet for Splunk. (chatgpt helped)
    """
    flat = {}
    layers = pkt.get("_source", {}).get("layers", {})

    # IP layer
    ip = layers.get("ip", {})
    flat["src_ip"] = ip.get("ip.src")
    flat["dst_ip"] = ip.get("ip.dst")

    # TCP/UDP layer
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})
    flat["src_port"] = tcp.get("tcp.srcport") or udp.get("udp.srcport")
    flat["dst_port"] = tcp.get("tcp.dstport") or udp.get("udp.dstport")

    # Protocol
    if tcp:
        flat["protocol"] = "TCP"
    elif udp:
        flat["protocol"] = "UDP"
    elif layers.get("icmp"):
        flat["protocol"] = "ICMP"
    else:
        flat["protocol"] = "OTHER"

    # Packet length
    frame = layers.get("frame", {})
    flat["length"] = frame.get("frame.len")

    return {k: v for k, v in flat.items() if v is not None}
    
SPLUNK_URL = "http://192.168.1.148:8088/services/collector/event"
HEC_TOKEN = "61e6443e-d3ea-41d9-b496-0c665f9f0772"
HEADERS = {"Authorization": f"Splunk {HEC_TOKEN}"}
JSON_DIR = "json_logs/"
    
def pcap_to_json(pcap_path, output_file):
	subprocess.check_call(["tshark", "-r", pcap_path, "-T", "json"], stdout=open(JSON_DIR + output_file,"wb"))
	with open(JSON_DIR + output_file, "r") as json_file:
		packets = json.load(json_file)
		return packets

def send_packets_json(packets_list):
	for packet in packets_list:
		flat_packet = flatten_packet(packet)
		payload = {"event": flat_packet, "sourcetype": "pcap_event", "index": "honeypot_packets"}
		
		requests.post(SPLUNK_URL, headers=HEADERS, data=json.dumps(payload), verify=False)
		
