""" project token : KotaFuzza
Copyright (c) 2019, Fabian Beck, Deutsche Telekom AG
contact: f.beck@t-systems.com
This file is distributed under the conditions of the MIT license.
For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel. """

__version__	= "0.6"

from scapy.all import sr1, rdpcap
from scapy.layers.inet import IP, ICMP
from subprocess import Popen, PIPE, run
import argparse
import os
import sys
import random
from re import search
from platform import system
import datetime
from time import sleep
from random import uniform
import multiprocessing
import threading
import nmap
import csv
import queue

class Fuzz_Preparation():

    def __init__(self, pcapfile, dir_raw, target_ip='127.0.0.1', offset=0, encryption=False, portscanfile = '../portscan.csv', portrange='10-100'):
        self._pcapfile = pcapfile
        self._dir_raw = dir_raw
        self._target_ip = target_ip
        self._offset = offset
        self._encryption = encryption
        self._portscanfile = portscanfile
        self._portrange = portrange

    #Does a nmap scan and write it to a csv file
    def scanports(self):
        print('[+] Start to scan Ports '+self._portrange+' from '+self._target_ip+' '+str(datetime.datetime.now()))
        try:
            nm = nmap.PortScanner()
            nm.scan(self._target_ip, self._portrange, arguments='-sS -sU -Pn')
        except KeyboardInterrupt:
            print('[-] Portscan was canceled manually by Keyboard')
        except nmap.nmap.PortScannerError:
            print("[-] Portscan needs Root Privileges!")
        try:
            f = open(self._portscanfile, 'w')
            f.write(nm.csv())
            print('[+] Scan complete')
        except IOError as err:
            return "[-] Error opening error file: %s" % str(err)
        print('[+] End of Portscan '+str(datetime.datetime.now()))

    def check_tls_app_data(self, payload):
        #Identification Application Data TLS/DTLS = \x17
        enc_app_data_hex = '17' #Application Data
        enc_handshake_hex = '16' #Encrypted Handshake
        enc_alert_hex = '15' #Encrypted Alerts
        enc_change_cipher_hex = '14' #Encrypted Change Cipher Spec
        payload_dump = payload.hex()[(self._offset*2):(self._offset*2+2)]
        if(payload_dump==enc_app_data_hex or payload_dump==enc_alert_hex or payload_dump==enc_handshake_hex or payload_dump==enc_change_cipher_hex):
            return True
        else:
            return False

    def parse_fuzz_packets(self):
        #Creates an Object of rdpcap for the configured pcap-file
        try:
            pcap = rdpcap(self._pcapfile)
            #List of sessions in pcap-file
            sessions = pcap.sessions()
            #Array used to safe useful payloads
            fuzz_payload=[]
            for session in sessions:
                #Select all IP Packets with TCP or UDP
                if ('TCP' in sessions[session][0] or 'UDP' in sessions[session][0]) and 'IP' in sessions[session][0]:
                    #Select only sessions with target ip as destination
                    if self._target_ip == sessions[session][0]['IP'].dst:
                        source_ip = sessions[session][0]['IP'].src
                        dest_port = sessions[session][0].dport
                        for packet in sessions[session]:
                            if'Raw' in packet:
                                payload = packet['Raw'].load
                                if 'UDP' in packet:
                                    transport_method = 'UDP'
                                elif 'TCP' in packet:
                                    transport_method = 'TCP'
                                else:
                                    transport_method = 'null'
                                if not [source_ip, dest_port, transport_method, payload] in fuzz_payload:
                                    if self._encryption == True and not self.check_tls_app_data(payload):
                                        fuzz_payload.append([source_ip, dest_port, transport_method, payload])
                                    elif self._encryption == False:
                                        fuzz_payload.append([source_ip, dest_port, transport_method, payload])
            return fuzz_payload    
        except FileNotFoundError:
            print('[-] File '+self._pcapfile+' not found!')
            exit(1)

    def createraws(self, packets):
        i = 1
        for packet in packets:
            try:
                f = open(self._dir_raw+packet[0]+'_to_'+self._target_ip+'_'+str(packet[1])+'_'+packet[2]+'_'+str(i)+'.raw','wb')
                f.write(packet[3])
                i += 1
                f.close
            except IOError as err:
                return "[-] Error opening error file: %s" % str(err)

    #Triggers the parsing of the pcap file
    def parse(self):
        print('[+] Start to parse payload from '+self._pcapfile)
        parsedpackets = self.parse_fuzz_packets()
        if parsedpackets:
            print('[+] Write payload files in '+self._dir_raw+' directory')
            self.createraws(parsedpackets) 
            print('[+] Parsing done! Payload files were created')
        else:
            print('[-] No usable payload found')


class Fuzz_Monitor():

    def __init__(self, target, mode, period, portscanfile, logfile, breakafterevent):
        self._mode = mode
        self._target = target
        self._period = period
        self._portscanfile = portscanfile
        self._logfile = logfile
        self._breakafterevent = breakafterevent
                
    #Checks if port is still alive. If not return False
    def portalive(self, transport, port):
        portstatus = ''
        try:                    
            portstatus = ''
            nm = nmap.PortScanner()
            if transport == 'udp':
                portstatus = nm.scan(self._target, port, arguments='-sU -Pn')['scan'][self._target]['udp'][int(port)]['state']
            elif transport == 'tcp':
                portstatus = nm.scan(self._target, port, arguments='-sS -Pn')['scan'][self._target]['tcp'][int(port)]['state']
            if portstatus == 'closed' or portstatus == 'filtered':
                self.log_monitor(str(datetime.datetime.now())+': '+transport+'/'+port+': '+portstatus)
                return False
            else:
                return True
        except nmap.nmap.PortScannerError:
            print("[-] Portscan needs Root Privileges!")
        except KeyError:
            self.log_monitor(str(datetime.datetime.now())+': '+self._target+' not reachable!')
        return False

    #Function for check via ping
    def icmpalive(self):
        try:
            TIMEOUT = 2
            pinger = IP(dst=self._target, ttl=20)/ICMP()
            reply = sr1(pinger, timeout=TIMEOUT, verbose=False)
            if (reply is None):
                self.log_monitor(str(datetime.datetime.now())+': No ICMP Reply.')
                return False
            else:
                return True
        except PermissionError:
            print("[-] ICMP Ping needs Root Privileges!")
            sys.exit(0)   
    
    #Gets the informations about the port via portscan csv file
    def getdatafromcsv(self):
        portdata = []
        try:
            with open(self._portscanfile,'r') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')
                for row in reader:
                    portdata.append([row['protocol'], row['port'], row['state']])
        except FileNotFoundError:
            print("[-] Portscan CSV File not found!")
        return portdata

    #Log Events
    def log_monitor(self, log_info):
        try:
            f = open(self._logfile, 'a')
        except IOError as err:
            return "[-] Error opening error file: %s" % str(err)
        if f:
            f.write(log_info+'\n')

    def run(self):
        self.log_monitor('Start of Fuzz: '+str(datetime.datetime.now()))
        if self._mode == 'portscan':
            fuzzobj = self.getdatafromcsv()
            while True:
                for row in fuzzobj:
                    if row[2] != 'filtered':
                        if not self.portalive(row[0], row[1]) and self._breakafterevent:
                            sys.exit(0)
                sleep(self._period)
        
        elif self._mode == 'icmp':
            while True:
                if not self.icmpalive() and self._breakafterevent:
                    sys.exit(0)
                sleep(self._period)
        else:
            print("[-] Wrong Monitor Mode!")
        self.log_monitor('End of Fuzz: '+str(datetime.datetime.now()))


class Fuzz():

    def __init__(self, target_ip='127.0.0.1', target_port=443, transport='tcp', dir_raw='../raw_packets/', seedsfile='../seeds.txt', maxseeds=200000, fuzz_delay=0, fuzz_delay_rand=False, monitor_mode='icmp', period=2, portscanfile='../portscan.csv', logfile='../log_monitor.log', breakafterevent=True):
        self._target_ip = target_ip
        self._target_port = target_port
        self._transport = transport

        self._dir_raw = dir_raw
       
        self._seedsfile = seedsfile
        self._maxseeds = maxseeds

        self._fuzz_delay = fuzz_delay
        self._fuzz_delay_rand = fuzz_delay_rand
        
        self._counter_packets = 0
        self._counter_animation = 0

        self._radamsa_bin = '/usr/local/bin/radamsa'
        if system() == 'Linux':
            self._radamsa_bin = '/usr/bin/radamsa'
        if not os.path.isfile(self._radamsa_bin):
            	sys.exit('[-] You need to install Radamsa for Fuzzing. Please install it from https://gitlab.com/akihe/radamsa')

        #Creates Daemon-Thread of Fuzz_Monitor
        self._monitor = Fuzz_Monitor(target_ip, monitor_mode, period, portscanfile, logfile, breakafterevent)
        self._tMonitor = threading.Thread(target=self._monitor.run)
        self._tMonitor.setDaemon(True)
    
    #Fuzz animation
    def animation_output(self, i):
        animation = "|/-\\"
        sys.stdout.write("\r" + animation[i % len(animation)])
        sys.stdout.flush()

    #returns event and error massages at the end
    def endfuzz_output(self, endevent, numpackets):
        print('[%]')
        if endevent == 'keyboard':
            print('[-] Fuzz was canceled manually by Keyboard')
        elif endevent == 'endseedfile':
            print('[-] There are no Seeds left')
        elif endevent == 'notreachable':
            print('[-] Target is not reachable '+str(datetime.datetime.now()))
        elif endevent == 'empty_raw':
            print('[-] The raw directory is emtpy')
        elif endevent == 'norawdir':
            print('[-] There is no raw directory with the name '+self._dir_raw)
        elif endevent == 'emptyseedfile':
            print('[-] Seedsfile is empty!')
        print('[+] End of Fuzz: '+str(datetime.datetime.now()))
        print("[+] "+str(numpackets)+" fuzzed packets were created")

    #Overloading function for specific use of radamsa 
    def mutate_payload(self):
        pass
    
    #Overloading function for start a specific fuzz method
    def start(self):
        pass


class Fuzz_Simple(Fuzz):

    def __init__(self, target_ip='127.0.0.1', target_port=443, transport='tcp', dir_raw='../raw_packets/', fuzz_delay=0, fuzz_delay_rand=False, monitor_mode='icmp', period=2, portscanfile='../portscan.csv', logfile='../log_monitor.log', breakafterevent=True):
        super().__init__(target_ip, target_port, transport, dir_raw, fuzz_delay=fuzz_delay, fuzz_delay_rand=fuzz_delay_rand, monitor_mode=monitor_mode, period=period, portscanfile=portscanfile, logfile=logfile, breakafterevent=breakafterevent)

    def mutate_payload(self, raw_file):
        try:
            if self._fuzz_delay_rand == True:
                self._fuzz_delay += round(uniform(0.01,4.00), 2)
            if self._fuzz_delay != 0:
                sleep(self._fuzz_delay)  
            run([self._radamsa_bin, '-o', self._target_ip+':'+str(self._target_port)+'/'+self._transport, self._dir_raw+raw_file])
            return True
        except:
            return False

    def start(self):
        print('[+] Start of Fuzz: '+str(datetime.datetime.now()))
        self._tMonitor.start()
        try:
            while self._tMonitor.isAlive():
                if os.listdir(self._dir_raw):
                    for raw_file in os.listdir(self._dir_raw):
                        if raw_file != '.DS_Store':
                            # rawport = raw_file.split('_')[1]
                            # if int(rawport) != self._target_port:
                            #     continue
                            if not self.mutate_payload(raw_file):
                                return self.endfuzz_output('keyboard', self._counter_packets)
                            if (self._counter_packets%100)==0:
                                self.animation_output(self._counter_animation)
                                self._counter_animation += 1
                            self._counter_packets += 1
                else:
                    return self.endfuzz_output('empty_raw', self._counter_packets)
            return self.endfuzz_output('reachable', self._counter_packets)
        except KeyboardInterrupt:
            return self.endfuzz_output('keyboard', self._counter_packets)
        except FileNotFoundError:
            return self.endfuzz_output('norawdir', self._counter_packets)


class Fuzz_with_Seeds(Fuzz):

    def mutate_payload(self, raw_file, seed, delay):
        try:
            if delay != 0:
                sleep(delay)
            run([self._radamsa_bin, '-s', seed, '-o', self._target_ip+':'+str(self._target_port)+'/'+self._transport, self._dir_raw+raw_file])
            return True
        except:
            return False

    def start(self):
        self._tMonitor.start()
        try:            
            if os.stat(self._seedsfile).st_size == 0:
                return super().endfuzz_output('emptyseedfile', self._counter_packets)
            print('[+] Open Seedfile')
            print('[+] Start of Fuzz: '+str(datetime.datetime.now()))
            with open(self._seedsfile,'r') as seeds_file:
                seeds_reader = csv.DictReader(seeds_file, delimiter=';')
                for row in seeds_reader:
                    if not self._tMonitor.isAlive():
                        return super().endfuzz_output('notreachable', self._counter_packets)
                    if not self.mutate_payload(row['rawfile'], row['seed'], float(row['delay'])):
                        return super().endfuzz_output('keyboard', self._counter_packets)
                    if (self._counter_packets%100)==0:
                        super().animation_output(self._counter_animation)
                        self._counter_animation += 1
                    self._counter_packets += 1
            return super().endfuzz_output('endseedfile', self._counter_packets)
        except KeyError:
            print("[-] Seedsfile needs Header in the first ĺine!")
        except FileNotFoundError:
            print("[-] Seedsfile not found!")
        except KeyboardInterrupt:
                seeds_file.close
                return super().endfuzz_output('keyboard', self._counter_packets)


class Fuzz_create_Seeds(Fuzz):

    def mutate_payload(self, raw_file): 
        #Delay until sending fuzzed packets
        if self._fuzz_delay_rand == True:
            self._fuzz_delay += round(uniform(0.01,4.00), 2)
        if self._fuzz_delay != 0:
            sleep(self._fuzz_delay)
        #Manipulate and send Fuzz to target
        try:   
            fuzzobj = run([self._radamsa_bin, '-v', '-o', self._target_ip+':'+str(self._target_port)+'/'+self._transport, self._dir_raw+raw_file], stdout = PIPE, stderr=PIPE)
            seedsearch = search(r'\d{10,}', str(fuzzobj.stderr))                
            if seedsearch:
                seed = seedsearch.group(0)
                fuzzlog = [raw_file, seed, self._fuzz_delay]
                return fuzzlog
            else:
                print('[-] Could not find seed!')
                sys.exit(1)
        except KeyboardInterrupt:
            return super().endfuzz_output('keyboard', self._counter_packets)

 
       

    def writequeueincsv(self, seeds_queue):
        with open(self._seedsfile, mode='w') as seedsfile:
            fieldnames = ['rawfile', 'seed', 'delay']
            seeds_writer = csv.DictWriter(seedsfile, fieldnames=fieldnames, delimiter=';')
            seeds_writer.writeheader()
            while not seeds_queue.empty():
                seedline = seeds_queue.get().split(';')
                seeds_writer.writerow({'rawfile': seedline[0], 'seed': seedline[1], 'delay': seedline[2]})
            seedsfile.close

    def start(self):
            self._tMonitor.start()
            seeds_queue = queue.Queue()
            try:
                print('[+] Start of Fuzz: '+str(datetime.datetime.now()))
                while self._tMonitor.isAlive():
                    if os.path.exists(self._seedsfile):
                        os.remove(self._seedsfile)
                    if os.listdir(self._dir_raw):
                        for raw_file in os.listdir(self._dir_raw):
                            if raw_file != '.DS_Store':
                                rawport = raw_file.split('_')[3]
                                if int(rawport) != self._target_port:
                                    continue
                                seed = self.mutate_payload(raw_file)
                                if self._counter_packets >= self._maxseeds:
                                    seeds_queue.get()
                                seeds_queue.put(seed[0]+';'+seed[1]+';'+str(seed[2]))
                                if (self._counter_packets%100)==0 or self._fuzz_delay_rand == True:
                                    super().animation_output(self._counter_animation)
                                    self._counter_animation += 1
                                self._counter_packets += 1
                    else:
                        return self.endfuzz_output('empty_raw', self._counter_packets)
                self.writequeueincsv(seeds_queue)
                return super().endfuzz_output('notreachable', self._counter_packets)

            except KeyboardInterrupt:
                self.writequeueincsv(seeds_queue)
                return super().endfuzz_output('keyboard', self._counter_packets)
