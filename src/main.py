import honeypot
import capture
import threading
import signal
import os 

LISTEN_ADDR = '0.0.0.0'
PORT = 2222

stop_event = threading.Event()
	
#print("Welcome to Honeypot\n1. Run Honeypot")

#choice = int(input("Enter an option: "))

#if choice == 1:

print("Welcome to Honeypot!")
if 1 == 1:
	pcap_name = input("Enter name of pcap file (without extension): ")
	pcap_filename = "pcap_logs/" + pcap_name + ".pcap"
	
	pcap_verbose = int(input("Enter 0 for simple or 1 for verbose pcap: "))
	print("Starting Honeypot...")
	print("Type 'q' to stop")
	
	tcpdump_process = capture.start_tcpdump(PORT, output_file = pcap_filename)
	
	hp_thread = threading.Thread(target = honeypot.start_honeypot, args = (LISTEN_ADDR, PORT, stop_event))
	hp_thread.start()
	
	while True:
		s = input().strip().lower()
		if s == 'q':
			stop_event.set()
			break
		
	hp_thread.join()
	tcpdump_process.send_signal(signal.SIGINT)
	tcpdump_process.wait()
	
	if os.path.getsize(pcap_filename) > 128:
		packets = capture.pcap_to_json(pcap_filename, pcap_name)
		capture.send_packets_json(packets)
		
	if pcap_verbose == 1:
		output_filepath = "readable_logs/verbose_readable_" + pcap_name + ".txt"
	else:
		output_filepath = "readable_logs/simple_readable_" + pcap_name + ".txt"
	
	with open (output_filepath, "w") as output_file:
		tshark_process = capture.pcap_to_txt(pcap_filename, pcap_verbose, output_file)
		tshark_process.wait()
	
else:
	print("Invalid choice")
