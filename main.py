import torch
import hashlib
import classifier
import numpy as np
import socket, sys, pickle
from struct import *
from threading import Timer
import multiprocessing as mp
from pathlib import Path
import os, subprocess
import json, logging
import datetime
import signal
import time

FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10
CPU_CORE = os.cpu_count()

PKT_CLASSIFIER = classifier.CNN_RNN()
PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
PKT_CLASSIFIER.eval()

HOST = 'localhost'
PORT = 50008
ser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ser.bind((HOST, PORT))
ser.listen(CPU_CORE)
clients = []
status_process = []
process_group = []
busy_process = 0

Lock = mp.Lock()

# def getflags( packet ):
#     # URG = packet & 0x020
#     # URG >>= 5
#     # ACK = packet & 0x010
#     # ACK >>= 4
#     # PSH = packet & 0x008
#     # PSH >>= 3
#     # RST = packet & 0x004
#     # RST >>= 2
#     # SYN = packet & 0x002
#     # SYN >>= 1
#     FIN = packet & 0x001
#     FIN >>= 0

#     return FIN

def get_key(pkt):
    key = ''

    eth_length = 14
    eth_header = pkt[: eth_length]
    eth = unpack( '!6s6sH' , eth_header )
    eth_protocol = socket.ntohs( eth[2] )

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
	    # Parse IP header
	    # take first 20 characters for the ip header
        ip_header = pkt[eth_length: 20+eth_length]
		
	    # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        s_addr = socket.inet_ntoa( iph[8] )

        d_addr = socket.inet_ntoa( iph[9] )

        key += "s_addr " + str( s_addr ) + " d_addr " + str( d_addr ) + ' '
        
        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = pkt[t: t+20]
            
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]

            key += "s_port " + str( source_port ) + " d_port " + str( dest_port )

        #ICMP Packets
        # elif protocol == 1:
            # check_protocol = True

            # u = iph_length + eth_length
            # icmph_length = 4
            # icmp_header = packet[u:u+4]

            # now unpack them :)
            # icmph = unpack( '!BBH' , icmp_header ) 
            
            # icmp_type = icmph[0]
            # code = icmph[1]
            # checksum = icmph[2]
        
        # UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udp_header = pkt[u:u+8]

            # now unpack them :)
            udph = unpack( '!HHHH' , udp_header )
            
            source_port = udph[0]
            dest_port = udph[1]

            key += "s_port " + str( source_port ) + " d_port " + str( dest_port )

        #some other IP packet like IGMP
        # else :
        #     print( 'Protocol other than TCP/UDP/ICMP' )

    return key
# get_key()

def run_server():
    global status_process

    #--------IPC-----------#
    for client_id in range(CPU_CORE - 1):
        process = subprocess.Popen(["python3", "client.py"])
        process_group.append(process)
        client, addr = ser.accept() 
        print("Client address:", addr)
        msg = ("My ID is " + str(client_id)).encode(encoding = 'utf-8')
        client.send(msg)
        client.setblocking(False)
        clients.append(client)
        status_process.append(0)
# run_server()    

def hash_key(key):
    new_key = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16) % (CPU_CORE - 1)
    return new_key
# hash_key

def check_idle():
    global busy_process
    global status_process

    while(True):
        for ID in range(CPU_CORE - 1):
            try:
                p_status = clients[ID].recv(4096)
                Lock.acquire()
                status_process[ID] = 0
                busy_process -= 1
                Lock.release()
                return ID
            except:
                pass
# check_idle()

def classify_pkt(flow, key): #will occur flow = [] status....
        
    global busy_process
    global status_process
    process_amt = CPU_CORE - 1

    if(busy_process < CPU_CORE - 1):
        # avaliable_pid = hash_key(key)
        avaliable_pid = time.process_time_ns() % process_amt
        while(status_process[avaliable_pid] == 1): #Linear probing, take no function call
            avaliable_pid = (avaliable_pid + 1) % process_amt

    else: #busy_process >=8
        avaliable_pid = check_idle()

    Lock.acquire()
    status_process[avaliable_pid] = 1
    busy_process += 1
    Lock.release()
    
    #print("AVALI = ", avaliable_pid)
    flowname = './buffer/flowbuffer-' + str(avaliable_pid)
    keyname = './buffer/keybuffer-' + str(avaliable_pid)

    #print((str(avaliable_pid) + "MAN FLOW = ") , flow)
    with open(flowname, 'wb') as f1:
        with open(keyname, 'wb') as f2:
            f1.truncate(0)
            f1.seek(0)
            f2.truncate(0)
            f2.seek(0)
            pickle.dump(flow, f1)
            pickle.dump(key, f2)

    clients[avaliable_pid].send(b'\x00')
    #print("PROCESS STATUS = ", status_process)

    flow.clear()
# classify_pkt()

def main():
    # open a socket
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs( 0x0003 ) )
    except socket.error as e:
        print( e )
        sys.exit()
    
    # create the log file directory if path is not exist
    Path("./log_file").mkdir(parents=True, exist_ok=True)
    log_filename = datetime.datetime.now().strftime(f"%Y-%m-%d.log")
    formate = json.dumps({"timestamp": "%(asctime)s.%(msecs)03d",
                          "source address": "%(s_addr)s",
                          "destination address": "%(d_addr)s",
                          "source port": "%(s_port)s",
                          "destination port": "%(d_port)s",
                          "class": "%(c)s",
                          "number of packets": "%(num_pkts)s"
    })
    logging.basicConfig(level=logging.INFO, filename="./log_file/" + log_filename, filemode='a',
                            format=formate,
                            datefmt='%Y/%m/%d %H:%M:%S'
    )

    global status_process
    global clients
    global busy_process
    flows = {}
    timers = {}
    recv_pkt_amt = 0

    run_server()
    ser.setblocking(False)

    def signal_handler(signum, frame):
        global busy_process
        global status_process
        global clients
        while(True):
            for ID in range(CPU_CORE - 1):
                try:
                    p_status = clients[ID].recv(4096)
                    Lock.acquire()
                    status_process[ID] = 0
                    busy_process -= 1
                    Lock.release()
                except:
                    pass
                
            stop = True
            for ID in range(CPU_CORE - 1):
                if(status_process[ID] == 1):
                    stop = False
                    break

            if(stop == True):
                s.close()
                ser.close()
                print("--------END PROCESS----------")
                break
        # while
        sys.exit(0)
    # signal_handler()

    # capture SIGINT signal to avoid the generating of the zombie processes
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        
        #-----RECV FROM DEVICE------#
        packet = s.recvfrom( 65565 )
        pkt = packet[0]
        key = get_key(pkt)
        
        #--------IPC-----------#
        for i in range(CPU_CORE - 1):
            try:
                p_status = clients[i].recv(4096)
                Lock.acquire()
                status_process[i] = 0
                busy_process -= 1
                Lock.release()
            except:
                pass

        if len( key ) != 0 and flows.get( key ) == None:
            flows[key] = [ pkt ]
            timers[key] = Timer(1.0, classify_pkt, (flows[key], key))
            timers[key].start()
        elif len( key ) != 0:
            timers[key].cancel()

            if len( flows[key] ) == 8:
                # do classification
                classify_pkt(flows[key], key)
            else:
                flows[key].append( pkt )
                timers[key] = Timer( 1.0, classify_pkt, (flows[key], key) )
                timers[key].start()
    # while
# main()

if __name__ == "__main__":
    main()