import socket, pickle
import torch
import classifier
import numpy as np
import logging
import multiprocessing as mp

FIRST_N_PKTS = 8
FIRST_N_BYTES = 80
BENIGN_IDX = 10
CPU_CORE = 8 # os.cpu_count()

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


msg = (s.recv(4096).decode(encoding = 'utf-8'))
for i in range(CPU_CORE - 1):
    if(msg == "My ID is " + str(i)):
        MYID = i
        print("MYID = ", MYID)
        break

flowname = './buffer/flowbuffer-' + str(MYID)
keyname = './buffer/keybuffer-' + str(MYID)

s.setblocking(False)

while(True):
    
    #----NonBlockiing----#
    try:
        # t_start = time.process_time()
        
        signal = s.recv(4096)
        if(signal == (b'')):
            s.close()
            break
        
        with open(flowname, 'rb') as f1:
            with open(keyname, 'rb') as f2:
                flow = pickle.load(f1)
                key = pickle.load(f2)
        
        dealt_flow = pkt2nparr(flow)
        flow2tensor = torch.tensor(dealt_flow, dtype=torch.float)
        output = PKT_CLASSIFIER(flow2tensor)
        _, predicted = torch.max(output, 1)

        print(f"predicted: {predicted[0]}")
        # class 10 represents the benign flow
        if predicted[0] != 10:
            lock.acquire()
            
            logger = logging.getLogger()
            filter_ = JsonFilter()
            logger.addFilter( filter_ )
            inf = key.split(' ')
            inf_len = len(inf)
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
        #print("Client" + str(MYID) + " successfully send..............")
    except ValueError:
        s.send(b'\x00')
        #print("Client" + str(MYID) + " successfully send..............")
    except:
        pass
# while
#print("SUM = ", Sum, ", line = ", line)
#f = open("performance.txt", "a")
#f.write(str(Sum) + ', ' + str(line) + '\n')
#f.close()

