import subprocess

def start_tcpdump(port, interface = 'eth0', output_file = 'logs/honeypot.pcap'):
	command = ['tcpdump', '-i', interface, '-s', '0', '-nn', 'port ' + str(port), '-w', output_file]
	
	return subprocess.Popen(command)

def pcap_to_readable(path_to_pcap, verbose, output_file):
	if verbose == 1:
		command = ["tshark", "-r", path_to_pcap, "-V"]
	else: 
		command = ["tshark", "-r", path_to_pcap]
		
	return subprocess.Popen(command, stdout = output_file)
