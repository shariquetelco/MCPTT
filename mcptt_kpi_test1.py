import pyshark
import argparse
import itertools
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
fig = plt.figure()
ax = fig.add_subplot(111)

request_time = 0
response_time = 0
file_name = ""
timestamp_tls_phone_to_server = []
timestamp_tls_server_to_phone = []
timestamp_tcp_phone_to_server = []
timestamp_tcp_phone_to_phone = []
call_control = []
floor_control = []
access_time = []

parser = argparse.ArgumentParser(description='Process the wireshark files')
parser.add_argument("pcap_name", help="Type the pcap file name to parse the data", type=str)
args = parser.parse_args()
pcap_file_name = args.pcap_name
current_path = Path.cwd()
file_name = str(current_path) + "/" + pcap_file_name
print(f"Path to pcap file : {file_name}")

def GenericFilter(name_file, filter):
	print("TLS filter : ", filter)
	capture = pyshark.FileCapture(name_file, display_filter=filter)
	#print(len(capture)) #Check why length is not working
	packet_and_timestamp = []
	for packet in capture:
		packet_and_timestamp.append((packet.number, float(packet.frame_info.time_epoch)))
	return(packet_and_timestamp)

def FloorControl(name_file, filter, data_to_get):
	packet_and_timestamp = []
	print(f"Data to get : {data_to_get}")
	for pkt in data_to_get:
		pkt_number = pkt[0]
		final_filter =  filter + pkt_number
		print(final_filter)
		capture = pyshark.FileCapture(name_file, display_filter=final_filter)
		packet_length = len([pkt for pkt in capture])
		if packet_length > 0:
			packet_and_timestamp.append((capture[0].number, float(capture[0].frame_info.time_epoch)))
		else:
			print("No Packets found. Packets are missing for floor control")
		capture.close()
		if capture.eventloop.run_until_complete:
			capture.close_async()
	print(packet_and_timestamp)
	return packet_and_timestamp

phone_src_ip = "12.1.1.3" #input("Provide the IP of the source phone : ")
serverip_ip = "169.55.65.207" #input("Provide the IP of the server : ")
phone_dst_ip = "169.45.211.199" #input("Provide the IP of the destination phone : ")


#phone_src_ip = "12.1.1.2" #input("Provide the IP of the source phone : ")
#serverip_ip = "169.45.211.199" #input("Provide the IP of the server : ")
#phone_dst_ip = "169.55.65.207" #input("Provide the IP of the destination phone : ")

call_control_from_phone = "ip.src=="+ phone_src_ip +" and ip.dst=="+ serverip_ip + " and tls.record.version==0x0303 and frame.len >= 1000 and frame.len<=1010"
call_control_from_server = "ip.src=="+ serverip_ip +" and ip.dst=="+ phone_src_ip + " and tls.record.version==0x0303 and frame.len >= 445 and frame.len<=500"
floor_control_to_server = "ip.src==" + phone_src_ip +" and ip.dst=="+ serverip_ip + " and tcp and not tls and frame.len >= 100"
floor_control_phone_to_phone = "ip.src==" + phone_src_ip + " and ip.dst==" + phone_dst_ip + " and frame.number>= "
timestamp_tls_phone_to_server = GenericFilter(file_name, call_control_from_phone)
print(f" Packet number and timestamp for call control from phone with tls : {timestamp_tls_phone_to_server}")
timestamp_tls_server_to_phone = GenericFilter(file_name, call_control_from_server)
print(f" Packet number and timestamp for call control from server with tls : {timestamp_tls_server_to_phone}")
timestamp_tcp_phone_to_server = GenericFilter(file_name, floor_control_to_server)
print(f" Packet number and timestamp for floor control from phone with TCP data : {timestamp_tcp_phone_to_server}")
timestamp_tcp_phone_to_phone = FloorControl(file_name, floor_control_phone_to_phone, timestamp_tcp_phone_to_server)
print(f" Packet number and timestamp for floor control from Phone to Phone with UDP data : {timestamp_tcp_phone_to_phone}")

if(len(timestamp_tls_phone_to_server)==len(timestamp_tls_server_to_phone)==len(timestamp_tcp_phone_to_server)==len(timestamp_tcp_phone_to_phone)):
	for (a,b,c,d) in zip(timestamp_tls_phone_to_server, timestamp_tls_server_to_phone, timestamp_tcp_phone_to_server, timestamp_tcp_phone_to_phone):
		call_control.append(float(b[1])-float(a[1]))
		floor_control.append(float(d[1])-float(c[1]))
	print(f"Over all Call control values received : {call_control}")
	print(f"Over all Floor Control values received : {floor_control}")
	for (i,j) in zip(call_control,floor_control):
		access_time.append(float(i)+float(j))
	print(f"Final Access Time values received : {access_time}")

elif (len(timestamp_tls_phone_to_server) > len(timestamp_tls_server_to_phone)):
	print("Packet Loss from TLS server to Phone in Call Control")
elif (len(timestamp_tls_phone_to_server) < len(timestamp_tls_server_to_phone)):
	print("Packet Loss from Phone to TLS server in Call Control")
elif (len(timestamp_tcp_phone_to_server) > len(timestamp_tcp_phone_to_phone)):
	print("Packet Loss from Phone to Phone for Floor control")
elif (len(timestamp_tcp_phone_to_server) < len(timestamp_tcp_phone_to_phone)):
	print("Packet Loss from Phone to Server for Floor control")	

number_of_samples = len(floor_control)
x = np.sort(floor_control)
print(f"sorted_data for floor control : {x}")
y = (np.arange(len(x)) / float(len(x)-1))*100
plt.xlabel('Floor Control Latency in Seconds')
#plt.xlim(0,0.02)
#plt.ylim(0,95)
plt.ylabel('CDF in %')
plt.title('KPI 1')
plt.plot(x, y, marker='o', color='r', markerfacecolor='blue', markersize=12, linewidth = 4, linestyle='dashed')
for i,j in zip(x,y):
    #ax.annotate('%s)' %j, xy=(i,j), xytext=(10,0), textcoords='offset points')
    ax.annotate('%s)' %i, xy=(i,j), xytext=(10,0), textcoords='offset points')
plt.plot(0.3, 95, "*")
plt.show()

'''
capture = pyshark.FileCapture('/Users/homestuck/Desktop/Freelancing/connection2.pcap', display_filter="s1ap")
for packet in capture:
	if hasattr(packet.s1ap, 'nas_eps_nas_msg_emm_type') and hasattr(packet.s1ap, 'nas_eps_nas_msg_esm_type'):
		if((int(packet.s1ap.nas_eps_nas_msg_emm_type)==int(65)) and (int(packet.s1ap.nas_eps_nas_msg_esm_type)==int(208))):
			request_time = float(packet.frame_info.time_epoch)
	if hasattr(packet.s1ap, 'successfuloutcome_element'):
		if (packet.s1ap.successfuloutcome_element == "successfulOutcome"):
			response_time = float(packet.frame_info.time_epoch)
			break
	else:
		continue	
if request_time == 0:
	print("No Initial EU request found")
if response_time == 0:
	print("No setup response found")
if response_time >= 1 and request_time >= 1:
	print(f"Request Time : {request_time} seconds")
	print(f"Response Time : {response_time} seconds")
	delta = (response_time - request_time)
	print(f"Delta = {delta} seconds")
'''