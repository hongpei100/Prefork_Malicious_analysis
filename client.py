import socket, pickle
import torch
import classifier
import numpy as np
import logging, json
import multiprocessing as mp
import os
import sys, signal
import datetime
from pathlib import Path

FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10
CPU_CORE = os.cpu_count()

lock = mp.Lock()

class JsonFilter(logging.Filter):
    s_addr = 's_addr'
    d_addr = 'd_addr'
    s_port = 's_port'
    d_port = 'd_port'
    c = 'class'
    num_pkts = 'num_pkts'

    def filter( self, record ):
        record.s_addr = self.s_addr
        record.d_addr = self.d_addr
        record.s_port = self.s_port
        record.d_port = self.d_port
        record.c = self.c
        record.num_pkts = self.num_pkts
        return True
# class JsonFilter

def pkt2nparr(flow):
    pkt_content = []

    for nth_pkt in range(min(len(flow), FIRST_N_PKTS)):
        idx = 0

        # get info of packet reading now
        for pkt_val in flow[nth_pkt]:
            if idx == 80:
                break

            pkt_content.append(pkt_val)
            idx += 1

        # if idx less than 80 after reading packet, then fill it with 0
        if idx < 80:
            while idx != 80:
                pkt_content.append(0)
                idx += 1

        # if nth_pkt is less than 8, then fill it with 0 too
        if nth_pkt == (len(flow) - 1) and nth_pkt < FIRST_N_PKTS-1:
            while nth_pkt != FIRST_N_PKTS-1:
                for _ in range(FIRST_N_BYTES):
                    pkt_content.append(0)
                #print("IN")

                nth_pkt += 1
        #print("OUT")
    # for end

    pkt2np = np.array(pkt_content).reshape(1, 8, 80)

    return pkt2np
# def pkt2nparr()

PKT_CLASSIFIER = classifier.CNN_RNN()
PKT_CLASSIFIER.load_state_dict(torch.load("pkt_classifier.pt", map_location=torch.device("cpu")))
PKT_CLASSIFIER.eval()

#Create a socket connection.
HOST = 'localhost'
PORT = 50008
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

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


msg = (s.recv(4096).decode(encoding = 'utf-8'))
for i in range(CPU_CORE - 1):
    if(msg == "My ID is " + str(i)):
        MYID = i
        print("MYID = ", MYID)
        break

flowname = './buffer/flowbuffer-' + str(MYID)
keyname = './buffer/keybuffer-' + str(MYID)

s.setblocking(False)

# pre-define varibles for signal_handler()
start_signal = b'0x01'
flow = []
key = ''

def signal_handler(signum, frame):

    # Instantly send the stop signal to main process,
    # and complete the work interrupted while receiving the SIGINT.
    s.send(b'\x00')

    try:
        if(start_signal == (b'')):
            s.close()
            sys.exit(0)
        
        with open(flowname, 'rb') as f1:
            with open(keyname, 'rb') as f2:
                flow = pickle.load(f1)
                key  = pickle.load(f2)
        
        dealt_flow = pkt2nparr(flow)
        flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
        output = PKT_CLASSIFIER(flow2tensor)
        _, predicted = torch.max(output, 1)

        # class 10 represents the benign flow
        if predicted[0] != 10:
            lock.acquire()
            
            logger = logging.getLogger()
            filter_ = JsonFilter()
            logger.addFilter( filter_ )
            inf = key.split(' ')
            if "s_addr" in inf:
                filter_.s_addr = inf[1]
                filter_.d_addr = inf[3]
                if "s_port" in inf:
                    filter_.s_port = inf[5]
                    filter_.d_port = inf[7]
            filter_.c = str( predicted[0] )
            filter_.num_pkts = len( flow )
            logger.info( key )
            lock.release()

        s.send(b'\x00')
    except ValueError:
        s.send(b'\x00')
    except:
        pass

    sys.exit(0)
# signal_handler()

signal.signal(signal.SIGINT, signal_handler)

while(True):
    
    #----NonBlockiing----#
    try:
        # t_start = time.process_time()
        
        start_signal = s.recv(4096)
        if(start_signal == (b'')):
            s.close()
            break
        
        with open(flowname, 'rb') as f1:
            with open(keyname, 'rb') as f2:
                flow = pickle.load(f1)
                key  = pickle.load(f2)
        
        dealt_flow = pkt2nparr(flow)
        flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
        output = PKT_CLASSIFIER(flow2tensor)
        _, predicted = torch.max(output, 1)

        # class 10 represents the benign flow
        if predicted[0] != 10:
            lock.acquire()
            
            logger = logging.getLogger()
            filter_ = JsonFilter()
            logger.addFilter( filter_ )
            inf = key.split(' ')
            if "s_addr" in inf:
                filter_.s_addr = inf[1]
                filter_.d_addr = inf[3]
                if "s_port" in inf:
                    filter_.s_port = inf[5]
                    filter_.d_port = inf[7]
            filter_.c = str( predicted[0] )
            filter_.num_pkts = len( flow )
            logger.info( key )
            lock.release()

        # t_end = time.process_time()
        # t_consume = t_end - t_start
        
        # print(f"\n******\nt_consume: {t_consume}\n******\n")

        s.send(b'\x00')
        #print("Client" + str(MYID) + " successfully send..............")
    except ValueError:
        s.send(b'\x00')
        #print("Client" + str(MYID) + " successfully send..............")
    except:
        pass
# while
