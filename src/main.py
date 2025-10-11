import honeypot
import capture
import threading
import signal

LISTEN_ADDR = '0.0.0.0'
PORT = 2222

stop_event = threading.Event()
	
#print("Welcome to Honeypot\n1. Run Honeypot")

#choice = int(input("Enter an option: "))

#if choice == 1:

print("Welcome to Honeypot!")
if 1 == 1:
	pcap_name = input("Enter name of pcap file (without extension): ")
	pcap_filename = "logs/" + pcap_name + ".pcap"
	
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
	
	if pcap_verbose == 1:
		output_filepath = "logs/verbose_readable_" + pcap_name + ".txt"
	else:
		output_filepath = "logs/simple_readable_" + pcap_name + ".txt"
	output_file = open(output_filepath, "w")
	tshark_process = capture.pcap_to_readable(pcap_filename, pcap_verbose, output_file)
	tshark_process.wait()
	output_file.close()
	
else:
	print("Invalid choice")
