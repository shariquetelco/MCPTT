import pyshark
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

def GenericFilter(name_file, filter):
	print("TLS filter : ", filter)
	capture = pyshark.FileCapture(name_file, display_filter=filter)
	#print(len(capture)) #Check why length is not working
	packet_and_timestamp = []
	for packet in capture:
		packet_and_timestamp.append([packet.number, float(packet.frame_info.time_epoch)])
	return(packet_and_timestamp)

file_name = input("Enter the file name to consider for kpi 3 : ")
current_path = Path.cwd()
file_name = str(current_path) + "/" + file_name
print(f" Path to pcap file : {file_name}")

filter1 = "ip.src == 12.1.1.2 and ip.dst == 169.45.211.199 and frame.len == 429"
filter2 = "(ip.dst == 12.1.1.2 and ip.src == 169.45.211.199 and tcp) && !(ssl.record.version == 0x0303)"
filter3 = "(ip.src == 169.55.65.207 and ip.dst == 12.1.1.2)"

timestamp_at_filter1 = []
timestamp_at_filter2 = []
timestamp_at_filter3 = []

timestamp_at_filter1 = GenericFilter(file_name, filter1)
print(f" Packet number and timestamp for filter1: {timestamp_at_filter1}")

timestamp_at_filter2 = GenericFilter(file_name, filter2)
print(f" Packet number and timestamp for filter2 : {timestamp_at_filter2}")

timestamp_at_filter3 = GenericFilter(file_name, filter3)
print(f" Packet number and timestamp for filter3 : {timestamp_at_filter3}")

total_packets_filter1 = len(timestamp_at_filter1)
print(f"Length of filter1 packets : {total_packets_filter1}")
total_packets_filter2 = len(timestamp_at_filter2)
print(f"Length of filter2 packets : {total_packets_filter2}")
total_packets_filter3 = len(timestamp_at_filter3)
print(f"Length of filter3 packets : {total_packets_filter3}")

initial_list = []
for i in range(total_packets_filter1):
    if i == total_packets_filter1-1:
        for m in range(total_packets_filter2):
            if int(timestamp_at_filter1[i][0])<int(timestamp_at_filter2[m][0]):
                for n in range(total_packets_filter3):
                    if int(timestamp_at_filter1[i][0])<int(timestamp_at_filter3[n][0]):
                        initial_list.append((float(timestamp_at_filter1[i][1]), float(timestamp_at_filter3[n][1])))
                        break
                    else:
                        continue
                break
            else:
                continue
    else:
        for j in range(total_packets_filter2):
            if int(timestamp_at_filter1[i][0])<int(timestamp_at_filter2[j][0])<int(timestamp_at_filter1[i+1][0]):
                for k in range(total_packets_filter3):
                    if (int(timestamp_at_filter1[i][0])<int(timestamp_at_filter3[k][0])<int(timestamp_at_filter1[i+1][0]) and (int(timestamp_at_filter2[j][0])<int(timestamp_at_filter3[k][0]))):
                        initial_list.append((float(timestamp_at_filter1[i][1]), float(timestamp_at_filter3[k][1])))
                        break
                    else:
                        continue
                break
            else:
                continue
print(initial_list)
print(f"Length of list {len(initial_list)}")

final_list = []
experimental_list = []
count = 0
kpi_value = 100 #Define the kpi value
for h in initial_list:
    final_value = (h[1]-h[0])*1000
    final_list.append(final_value)
    if final_value < kpi_value:
        count += 1
        experimental_list.append(final_value)
print(f"Final KPI2 values : {final_list}")

if count != 0:
    total_samples = (count/len(final_list))*100
    experimental_samples = (count/len(experimental_list))*100

number_of_samples = len(final_list)
x = np.sort(final_list)
z = np.sort(experimental_list)
print(f"sorted_data for floor control : {x}")

y = (np.arange(len(x)) / float(len(x)-1))*100
plt.xlabel('E2E Latency in milli Seconds')
plt.ylabel('CDF in %')
plt.title(f'KPI 3 - {total_samples} % values lies within {kpi_value}ms')
plt.plot(x, y, marker='o')
#plt.xticks([0.5,1,1.5,2,2.5,3,3.5,4,4.5])
plt.show()

y = (np.arange(len(z)) / float(len(z)-1))*100
plt.xlabel('E2E Latency in milli Seconds')
plt.ylabel('CDF in %')
plt.title(f'KPI 3 - {experimental_samples} % values lies within {kpi_value}ms')
plt.plot(z, y, marker='o')
#plt.xticks([0.5,1,1.5,2,2.5,3,3.5,4,4.5])
plt.show()