import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send("hello\r\n")

		results = connSkt.recv(100)
		screenLock.acquire()
		print "[+] Port: " + str(tgtPort) + " is open"
		numPorts += 1

	except:
		screenLock.acquire()
		#print "[-] Port: " + str(tgtPort) + " is closed"

	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve host: " + tgtHost
		return

	try:
		tgtName = gethostbyaddr(tgtIP)
		print "\n[+] Scan results for: " + tgtName[0]
	except:
		print "\n[+] Scan results for: " + tgtIP
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()

def Main():
	parser = optparse.OptionParser("usage %prog -H <target host> -p <target port>")
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s], separated by a comma or ranges with a dash')
	(options, args) = parser.parse_args()
	if(options.tgtHost == None or options.tgtPort == None):
		print parser.usage
		exit(0)
	else:
		tgtHost = options.tgtHost
		if '-' in str(options.tgtPort):
			tgtPorts = options.tgtPort.split('-')
			tgtPorts = range(int(tgtPorts[0]),int(tgtPorts[1]))
		else:
			tgtPorts = str(options.tgtPort).split(',')

	portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	Main()