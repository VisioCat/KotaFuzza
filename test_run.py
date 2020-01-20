from KotaFuzza import Fuzz_Preparation, Fuzz_with_Seeds, Fuzz_create_Seeds, Fuzz_Simple

TARGETIP = '192.168.0.1'
TARGETPORT = 443
TARGETTRANSPORT = 'udp'
TLSon = True
PCAP_FILE = '../trace1.pcapng'
RAW_DIR = '../raw_packets/'
SEED_FILE = '../seeds.csv

#x = Fuzz_Preperation(PCAP_FILE, RAW_DIR, TARGETIP, TLSOFFSET, TLSon)
#x.parse()

#firstfuzz = Fuzz_create_Seeds(TARGETIP, TARGETPORT, TARGETTRANSPORT, RAW_DIR, SEED_FILE)
#firstfuzz.start()

#secondfuzz = Fuzz_with_Seeds(TARGETIP, TARGETPORT, TARGETTRANSPORT, RAW_DIR, SEED_FILE)
#secondfuzz.start()
