from matplotlib import markers
import matplotlib.pyplot as plt
import numpy as np

speed_of_light = 300000000
cqi = { 1:(15, 0.9258),
        2:(15, 0.9258),
        3:(15, 0.9258),
        4:(14, 0.8525),
        5:(14, 0.8525),
        6:(13, 0.7539),
        7:(12, 0.6504),
        8:(12, 0.6504),
        9:(12, 0.6504),
        10:(11, 0.5537),
        11:(10, 0.4551),
        12:(9, 0.6016),
        13:(9, 0.6016),
        14:(8, 0.4785),
        15:(7, 0.3691),
        16:(6, 0.5879),
        17:(5, 0.4385),
        18:(4, 0.3008),
        19:(3, 0.1885),
        20:(2, 0.1172),
        21:(1, 0.0762)
        }


phone = int(input("""Transmitter Phone
            1. Xiaomi 
            2. Google 
Enter your input in number : """))
if phone == 1 or phone == 2:
    if(phone == 1):
        tcp_packet = 232
    elif(phone == 2):
        tcp_packet = 356
    tcp_header = 20    
    hop= float(input("number of hops : "))
    distance = int(input("Enter phone distance between 1 to 21 : "))
    if distance in cqi.keys():
        Dprop = distance/speed_of_light
        packet_size = (tcp_packet+tcp_header)*8
        modem_rate = cqi[distance][1] * 1024
        Dtrans = packet_size/modem_rate
        M2E = (hop+1)*Dprop + hop*Dtrans
        print(" Mouth to Ear Latency is : ", M2E)
    else:
        print("The distance is not present in the CQI table")
else:
    print("The number is Invalid")

plt.xlim(0,21)
#plt.xticks(range(0,22,2))
plt.scatter(distance, M2E, marker ="o")
plt.show()
