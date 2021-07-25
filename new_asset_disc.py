import shlex
import subprocess
import getopt
import socket
import sys
import os
import re
import json
import time
from pwn import *
from datetime import datetime

def get_var_value(filename="counter.dat"):
	with open(filename, "a+") as f:
		f.seek(0)
		val = int(f.read() or 0) + 1
		f.seek(0)
		f.truncate()
		f.write(str(val))
		return val
def create_tunnel():
	print("You neet to be root in both machines for this.")
	user_name = str(input("Enter user name with root privellege in remote machine: "))
	ip = str(input("Enter IP address of SSH server: "))
	port = str(input("Enter port of SSH service: "))
	print("Run the folowing command in a new terminal.")
	cmd = "sudo ssh -p "+ port + " -D 55555 " + user_name + "@" + ip
	cmd = " ".join(cmd.split("\n")[:-2])
	cmd += "@"
	cmd += ip
	print(cmd)

	print("Add the following in the /etc/proxychains4.conf: ")
	print("socks4 	127.0.0.1 55555")
	print("Comment out the proxy_dns in /etc/proxychains4.conf")

	ans = input("Enter (Y/N): ")
	while ans != "Y\n":
		ans = input("Enter (Y/N): ")




def get_nmap_path():
	os_type = sys.platform
	if os_type == 'win32':
		cmd = "where nmap"
	else:
		cmd = "which nmap"
	args = shlex.split(cmd)
	sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
	try:
		output, errs = sub_proc.communicate(timeout=15)
	except Exception as e:
		print(e)
		sub_proc.kill()
	else:
		if os_type == 'win32':
			return output.decode('utf8').strip().replace("\\", "/")
		else:
			return output.decode('utf8').strip()

def run_command(shell_cmd):
	path=get_nmap_path()
	if os.path.exists(path):
		sub_proc = subprocess.Popen(shell_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		try:
			output, errs = sub_proc.communicate()
		except Exception as e:
			sub_proc.kill()
			raise (e)
		else:
			if 0 != sub_proc.returncode:
				raise ValueError("Error while running command")
			return output.decode('utf8').strip()
	else:
		raise ValueError("Nmap is either not installed or we couldn't locate nmap path Please ensure nmap is installed")

def scan_ports(ip):
	cmd = "nmap {target}".format(target=ip)
	scan_shlex = shlex.split(cmd)
	output = run_command(scan_shlex)
	new_str = ""

	if not output:
		raise ValueError("Unable to perform port scan.")
	out = output.split("\n")
	time_str = str(out[-1]).split()
	time_taken = " ".join(time_str[-2:])
	out = out[4:-2]
	for i in range(len(out)):
		print(out[i])
	ports_json = json.dumps(out[1:-1])
	if len(out) == 0:
		print("No open ports detected")
		new_str += '"ports":"No open ports found"'	
	else:
		new_str += '"ports":'+ ports_json
	print(f"Total time taken to scan ports and services: {time_taken}\n")
	return new_str

def scan_os(ip):
	cmd = "nmap -O {target}".format(target=ip)
	scan_shlex = shlex.split(cmd)
	output = run_command(scan_shlex)
	if not output:
		raise ValueError("Unable to detect Operating System.")
	out = output.split("\n")
	time_str = str(out[-1]).split()
	time_taken = " ".join(time_str[-2:])
	out = out[13:-3]
	if len(out) == 0 or "No exact OS matches for host" in output or (len(out) == 1 and "hop" in output):
		print("Unable to detect Operating System.")
		new_str = '"os":"No exact OS matches for host."'
		return new_str
	os_json = json.dumps(out)
	new_str = '"os":' + os_json
	print("#### Guessed Operating System ####")
	for i in range(len(out)):
		if "hop" not in out[i]:
			print(out[i])
	
	print("##################################")
	print(f"Total time taken to guess OS: {time_taken}\n")
	return new_str

def scan_remote_host(hosts):
	final_str = ""
	for host in hosts:
		ids = get_var_value()
		index_str = '{"index":{"_index":"assets","_id":'+ str(ids) +'}}\n'
		print(f"######## {host} ########")
		cmd = f"proxychains4 nmap -Pn -O {host}"
		scan_shlex = shlex.split(cmd)
		output = run_command(scan_shlex)
		if not output:
			raise ValueError("Unable to scan hosts.")
		out = output.split("\n")
		ports = []
		os = []
		if out[4].split()[0] == "PORT":
			i = 5
			while out[i].split()[1] == "open":
				ports.append(out[i])
				i += 1
		if "OS CPE:" in output:
			indx = 5
			for i in range(indx, len(out)):
				if "OS CPE" in out[i]:
					indx = i
					break
				i+=1
			os.append(out[i])
			os.append(out[i+1])
		print("[>] Scanning ports and services.")
		ports_json = json.dumps(ports)
		os_json = json.dumps(os)
		ports_str =""
		os_str = ""
		if ports == []:
			ports_str = '"ports":"No open ports found"'
			print("No open ports found.")
		else:
			ports_str = '"ports":'+ ports_json
			for i in range(len(ports)):
				print(ports[i])
		print("[>] Scanning Operating System.")
		if os == []:
			os_str = '"os":"No exact OS matches for host."'
			print("No exact OS matches for host.")
		else:
			for i in range(len(os)):
				print(os[i])
			os_str = '"os":' + os_json
		print("########################")
		now = datetime.now()
		final_str += index_str
		time_str = '"lastseen":"' + str(now) + '"'
		new_str = '{"ip":"' + host + '", "type": "remote"' + ', ' + ports_str + ', ' + os_str + time_str + '}\n'
		final_str += new_str
	
	print(final_str)
	sys.exit()

def discover_remote_hosts(range):
	print("This may take time:")
	cmd = f"proxychains4 nmap -sP {range}"
	scan_shlex = shlex.split(cmd)
	output = run_command(scan_shlex)
	if not output:
		raise ValueError("Unable to scan hosts.")
	ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
	out = output.split("\n")
	ips = []
	for s in out:
		if ip_pattern.search(str(s)) == None or ip_pattern.search(str(s))[0] in ips:
			continue
		ips.append(ip_pattern.search(str(s))[0])
	print(f"Found {len(ips)} hosts.")
	scan_remote_host(ips)




def scan_remote(range):
	create_tunnel()
	hosts = []
	n = int(input("Enter number of known hosts, if any:"))
	hosts = list(map(str,input("\nEnter the host IPs : ").strip().split()))[:n]
	if hosts == []:
		discover_remote_hosts(range)
	else:
		scan_remote_host(hosts)

def scan_ip(ip):
	cmd = f"nmap -O {ip}"
	scan_shlex = shlex.split(cmd)
	output = run_command(scan_shlex)
	if not output:
		raise ValueError("Unable to scan host.")
	out = output.split("\n")
	ports = []
	os = []
	i = 5
	if out[4].split()[0] == "PORT":
		while out[i].split()[1] == "open":
			ports.append(out[i])
			i += 1
	if "OS CPE:" in output:
		indx = 5
		for i in range(indx, len(out)):
			if "OS CPE" in out[i]:
				indx = i
				break
			i+=1
		os.append(out[i])
		os.append(out[i+1])
	
	return ports,os


def scan_range(range, local, remote):
	if local == True:
		print("[*] Scanning hosts in this network")
		cmd = "nmap -sP {target}".format(target=range)
		scan_shlex = shlex.split(cmd)
		output = run_command(scan_shlex)
		if not output:
			raise ValueError("Unable to scan hosts.")
		ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
		mac_pattern = re.compile(r'(?:[0-9a-fA-F]:?){12}')
		ips = []
		hosts = {}
		out = output.split("\n")
		for s in out:
			if ip_pattern.search(str(s)) == None or ip_pattern.search(str(s))[0] in ips:
				continue
			ips.append(ip_pattern.search(str(s))[0])
		for ip in ips:
			pid = subprocess.Popen(["arp", "-n", ip], stdout=subprocess.PIPE)
			s = str(pid.communicate()[0])
			if mac_pattern.search(s) == None:
				hosts[ip] = "Error finding MAC"
				continue
			mac = mac_pattern.search(s)[0]
			hosts[ip] = mac
		host_json = json.dumps(hosts)
		print(f"Found {len(hosts)} hosts.")
		final_str = ""
		for host in hosts:
			ports_str = ""
			os_str = ""
			ids = get_var_value()
			index_str = '{"index":{"_index":"assets","_id":'+ str(ids) +'}}\n'
			print(f"######### {host} #########")
			
			print("[>] Scanning ports and services")
			ports,os = scan_ip(host)
			for port in ports:
				print(port)
			if len(ports) == 0:
				print("No open ports detected.")
				ports_str = '"ports":"No open ports detected."'
			else:
				ports_json = json.dumps(ports)
				ports_str = '"ports":'+ports_json
			print("MAC Address: ", hosts[host])
			print("[>] Scanning Operating System")
			for o in os:
				print(o)
			if len(os) == 0:
				print("Error detecting Operating System.")
				os_str = '"os":"Error detecting Operating System."'
			else:
				os_json = json.dumps(os)
				os_str = '"os":' + os_json
			mac_str = '"mac":"'+hosts[host] + '"'
			now = datetime.now()
			print("#################################")
			time_str = '"lastseen":"' + str(now) + '"'
			host_str = ""

			try:
				hostname = socket.gethostbyaddr(host)
				host_str = '"hostname":"' + str(hostname[0]) + '"'
			except:
				host_str = '"hostname":"Unable to detect host-name"'
			new_str = '{"ip":"' + host + '", "type": "local"' + ', ' + mac_str + ', ' + ports_str + ', ' + os_str + ', ' + host_str + ', ' + time_str + '}\n'
			final_str += index_str + new_str
			time.sleep(5)
		print(final_str)
		sys.exit()
	elif remote == True:
		scan_remote(range)
	else:
		print('Usage:\n./asset_discovery.py [--local | --remote] [--ip <IP address> | --range <IP range> | --url <url>]\n')
		sys.exit()



def main(argv):
	local = False
	remote = False
	url = False
	U = ""
	if len(argv) == 0:
		print('Usage:\n./asset_discovery.py [--local | --remote] [--ip <IP address> | --range <IP range> | --url <url>]\n')
		print("Example:\n./asset_discovery.py --url www.google.com\n./asset_discovery.py --local --range 10.10.10.0/24\n./asset_discovery.py --ip 10.10.10.2")
		sys.exit(2)
	try:
		opts, args = getopt.getopt(argv, "h", ["ip=", "url=", "range=", "local", "remote"])
	except getopt.GetoptError:
		print('Usage:\n./asset_discovery.py [--local | --remote] [--ip <IP address> | --range <IP range> | --url <url>]\n')
		print("Example:\n./asset_discovery.py --url www.google.com\n./asset_discovery.py --local --range 10.10.10.0/24\n./asset_discovery.py --ip 10.10.10.2")
		sys.exit(2)
	for opt,arg in opts:
		if opt == '-h':
			print('Usage:\n./asset_discovery.py [--local | --remote] [--ip <IP address> | --range <IP range> | --url <url>]\n')
			print("Example:\n./asset_discovery.py --url www.google.com\n./asset_discovery.py --local --range 10.10.10.0/24\n./asset_discovery.py --ip 10.10.10.2")
			sys.exit(2)
		elif opt == '--ip':
			ip = arg
			print("Target IP address: ", ip)
		elif opt == '--url':
			url = True
			url_str=arg
			U = arg
			ip = socket.gethostbyname(url_str)
			print("Target IP address: ", ip)
		elif opt == '--range':
			range = arg
			scan_range(range, local, remote)
		elif opt == '--local':
			local = True
		elif opt == '--remote':
			remote = True
	ip = str(ip).strip()
	ids = get_var_value()
	print("[*] Enumerating ports and service: ")
	final_str = ""
	final_str += '{"index":{"_index":"assets","_id":'+ str(ids) +'}}\n'
	ids += 1
	ports_str = scan_ports(ip)
	print("[*] Enumerating Operating system: ")
	os_str = scan_os(ip)
	ip_str = '{"ip":"' + ip + '", ' + '"type": "IP/URL", '
	if url == True:
		ip_str += '"url":"' + U + '", '
	now = datetime.now()
	time_str = '"lastseen":"' + str(now) + '"'
	host_str = ""

	try:
		hostname = socket.gethostbyaddr(ip)
		host_str = '"hostname":"' + str(hostname[0]) + '"'
	except:
		host_str = '"hostname":"Unable to detect host-name"'


	ip_str += ports_str + ', ' + os_str + ', ' + host_str + ', ' + time_str +'}\n'
	final_str += ip_str
	print(final_str)


if __name__ == '__main__':
	main(sys.argv[1:])
