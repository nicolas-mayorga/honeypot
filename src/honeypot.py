import socket
import sys
from datetime import datetime
import threading
import time
import random


def log_connection(addr, data):
    with open("logs/honeypot.logs", "a") as f:
        f.write(f"{datetime.now()} - Connection from {addr} - Data: {data}\n")

def random_banner():
	banners = [
		b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n",
		b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
		b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n",
		b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n",
		b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2\r\n",
		b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u3\r\n",
		b"SSH-2.0-OpenSSH_9.2p1 Debian-1\r\n",
		b"SSH-2.0-OpenSSH_9.3p1 Debian-1+b1\r\n",
		b"SSH-2.0-OpenSSH_9.0p1 Debian-1\r\n",
		b"SSH-2.0-OpenSSH_8.0p1 RedHat-9.el8\r\n",
		b"SSH-2.0-OpenSSH_8.7p1 RedHat-6.el9\r\n",
		b"SSH-2.0-OpenSSH_7.4p1 RedHat-22.el7_9\r\n",
		b"SSH-2.0-OpenSSH_8.0p1 CentOS-6.el8\r\n",
		b"SSH-2.0-OpenSSH_7.4p1 CentOS-21.el7\r\n",
		b"SSH-2.0-OpenSSH_9.0p1 Fedora-2.fc39\r\n",
		b"SSH-2.0-OpenSSH_8.8p1 Fedora-1.fc37\r\n",
		b"SSH-2.0-OpenSSH_9.3p1 Fedora-1.fc40\r\n",
		b"SSH-2.0-OpenSSH_8.6p1 Arch\r\n",
		b"SSH-2.0-OpenSSH_9.1p1 Arch\r\n",
		b"SSH-2.0-OpenSSH_9.0p1 Manjaro\r\n",
		b"SSH-2.0-OpenSSH_8.4p1 Kali-2\r\n",
		b"SSH-2.0-OpenSSH_9.3p1 Kali-1\r\n",
		b"SSH-2.0-OpenSSH_8.2p1 LinuxMint-1ubuntu0.9\r\n",
		b"SSH-2.0-OpenSSH_9.0p1 AlmaLinux-6.el9\r\n",
		b"SSH-2.0-OpenSSH_9.3p1 Rocky-7.el9\r\n",
		b"SSH-2.0-OpenSSH_7.8p1 AmazonLinux-4.amzn2\r\n",
		b"SSH-2.0-OpenSSH_8.0p1 SUSE-3.14.3\r\n",
		b"SSH-2.0-OpenSSH_8.6p1 openSUSE-1.2\r\n",
		b"SSH-2.0-OpenSSH_9.3p1 Alpine-1\r\n",
		b"SSH-2.0-OpenSSH_8.8p1 Alpine-2\r\n",
	]
	return random.choice(banners)
	
	
def send_login(conn, addr):
    with conn:
        print(f"Connection from {addr}")
        conn.sendall(random_banner())
        time.sleep(1)
        try:
            conn.sendall(b"Username: ")
            username = conn.recv(1024).decode().strip()
            time.sleep(1)
            psswd_prompt = f"Password for user {username}: "
            conn.sendall(psswd_prompt.encode())
            password = conn.recv(1024).decode().strip()
            time.sleep(2)
            log_connection(addr, "Username: " + username + " / Password: " + password)
            loggedin_msg = f"Successfully logged in as {username}!\n"
            conn.sendall(loggedin_msg.encode())
            shell_prompt = f"{username}@server1:~$ "
            conn.sendall(shell_prompt.encode())
            data = conn.recv(1024).decode() + "\n"
            log_connection(addr, data)
            
        except Exception as e:
            print(f"Error: {e}")


def start_honeypot(listening_address, port, stop_event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    	s.bind((listening_address, port))
    	s.listen()
    	s.settimeout(1.0)
    	print(f"Honeypot listening on {listening_address}: {port}")
    	
    	try:
    		while not stop_event.is_set():
    			try:
    				conn, addr = s.accept() 
    				threading.Thread(target = send_login, args = (conn, addr), daemon = True).start() 
    			except socket.timeout:
    				continue
    	
    	finally:
    		s.close()
    		print("Honeypot Stopped")         
