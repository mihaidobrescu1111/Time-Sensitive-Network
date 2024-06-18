from scapy.all import *
from random import randint
import threading

t = time.time
def send_packets():
    while True:
        p = randint(0, 7)
        vlan_pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / Dot1Q(vlan=10, prio=p) / IP(src="192.168.1.1", dst="192.168.1.2") / ICMP()
        sendp(vlan_pkt, iface="wlo1")
        time.sleep(0.05)
    

def main():
    # Number of threads for sending packets concurrently
    num_threads = 5
    
    # Create and start multiple threads for sending packets
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_packets)
        thread.daemon = True  # Set threads as daemon so they exit when main thread exits
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
