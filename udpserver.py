import struct
import random
import sys
import socket
import re
class dnshandler(object):
	'''
	HEADER 
	'''
	'''
	# 2 BYTE ID
	ID = random.randint(0,65536)
	# 1 BIT QR   0 represent query ,1 represent response
	QR = 1
	# 4 BIT OPCODE
	OPCODE = 0
	# 1 BIT AA
	AA = 0
	# 1 BIT TC
	TC = 0
	# 1 BIT RD
	RD = 1
	# 1 BIT RA
	RA = 0
	# 3 BIT Z
	Z = 0
	# 4 BIT RCODE  0 represent no error 3 represent name error
	RCODE = 0
	# 2 BYTE QD
	QDCOUNT = 1
	# 2 BYTE AN
	ANCOUNT = 0
	# 2 BYTE NS
	NSCOUNT = 0
	# 2 BYTE AR
	ARCOUNT = 0
	# X byte name
	# formmat:count(1 byte) + section + count(1 byte) + section ... + 0(1 byte)
	QNAME = []
	# 2 BYTE QTYPE
	QTYPE = 1
	# 2 BYTE QCLASS
	QCLASS = 1
	'''

	'''
	RR SECTION
	'''
	'''
	# 2 BYTE NAME
	NAME = ''
	# 2 BYTE TYPE
	TYPE = 1
	# 2 BYTE CLASS
	CLASS = 1
	# 4 BYTE TTL
	TTL = 5
	# 2 BYTE RDLENGTH
	RDLENGTH = 4
	# 4 BYTE RDATA  represent ip
	RDATA = ''
	'''
	res = ''
	def __packrname(self,rname):
		if len(rname) >= 2:
			tname = (rname[0]+rname[1]).split('.')
		else:
			tname = rname[0].split('.')
		res = '' 
		for x in tname:
				if len(x) >= 1:
					res += struct.pack('B',len(x))
				i = 0
				while i < len(x):
					res += struct.pack('c',x[i])
					i+=1
		res += struct.pack('B',0)
		return res
	def __init__(self,ID,rname,rip,Flag=0):
		if Flag == 1:
			self.res = struct.pack('H',ID)
			self.res += struct.pack('!2B4H',0x81,0x83,1,0,1,0)
			self.res += self.__packrname(rname)
			self.res += struct.pack('!2HB2HIH',1,1,0,1,1,5,4)
		else:	
			self.res = struct.pack('H',ID)
			self.res += struct.pack('!2B4H',0x81,0x80,1,1,0,0)
			self.res += self.__packrname(rname)
			# if len(rname) >= 2:
			# 	tname = (rname[0]+rname[1]).split('.')
			# else:
			# 	tname = rname[0].split('.')
			# # print tname
			# # if len(tname) == 1:
			# # tname.append('localdomain')
			# for x in tname:
			# 	if len(x) >= 1:
			# 		self.res += struct.pack('B',len(x))
			# 	i = 0
			# 	while i < len(x):
			# 		self.res += struct.pack('c',x[i])
			# 		i+=1
			self.res += struct.pack('!5HIH',1,1,0xc00c,1,1,5,4)
			# self.res += struct.pack('4BH',0,0,0,5,4)
			tip = rip.split('.')
			for x in tip:
				self.res += struct.pack('B',int(x))
	

def match1(str1,str2):
	if re.match(r'%s'%str1,str2):
		return [re.match(r'%s'%str1,str2).group(1),re.match(r'%s'%str1,str2).group(2)]
	else:
		return None
'''
UDP SERVER
'''
HOST = ''  
PORT = 53

try:
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.bind((HOST, PORT))
	
except socket.error,msg:
	print 'Failed to create socket.Error code: ' + str(msg[0]) + 'Error message:' + str(msg[1])
	sys.exit()

print 'server is now waiting'
buff,addr = s.recvfrom(4096)
print addr
# print struct.unpack('B3c',buff[12:16])
coo = [0,0,0,0,0,0]
rname = ''
pointer = 12
ID = struct.unpack('H',buff[:2])[0]
print ID
coo[0], = struct.unpack('B',buff[pointer])
i=0
while coo[i] != 0 and i < 6:
	if i!= 0:
		rname += '.'
	fmt = '%dc'%coo[i]
	name = struct.unpack('%dc'%coo[i],buff[(pointer+1):(pointer+coo[i]+1)])
	for x in name:
		rname += x
	pointer += coo[i]+1
	i += 1
	coo[i], = struct.unpack('B',buff[pointer])


# if re.match('([^\.]*)\.localdomain',rname):
# 	rname = re.match('(.*)\.localdomain',rname).group(1)
rname = [rname]
rname = match1('(.*)(\.localdomain)',rname[0]) or \
	    match1('(.*)(\.bupt\.edu\.cn)',rname[0]) or \
	    rname
print rname	    

# if re.match(r'(www)*\.*([^.]*)\.*(.*)',rname):
# print rname
# rname = rname.strip('.localdomain')
# print 'after srip' + rname

'''
search dnsrelay for record
'''
fp = open('dnsrelay.txt','r')
records = fp.readlines()
rip = ''
for x in records:
	col = x.strip('\r\n').split(' ')
	if len(col) >= 2:
		if col[1] == rname[0]:
			rip = col[0]
			print 'Founded ' + 'ip:'+ rip
	else:
		pass
'''
send response
'''
if rip == '0.0.0.0':
	dnsres = dnshandler(ID,rname,rip,1).res
	a=[0]
	a.append(dnsres)
	print a 
	s.sendto(dnsres,addr)
	print 'sended ' + str(len(dnsres)) +' bytes'
	print 'No DNS Record'
elif rip == '':

	DNSHOST = '8.8.8.8'
	PORT2 = 53
	addr1 = (DNSHOST, PORT2)
	s.sendto(buff,addr1)
	buff1,addr2 = s.recvfrom(4096)
	s.sendto(buff1,addr)
	print addr2
	print buff1
else:
	dnsres = dnshandler(ID,rname,rip).res
	a=[0]
	a.append(dnsres)
	print a 
	s.sendto(dnsres,addr)
	print 'sended ' + str(len(dnsres)) +' bytes'
# print records
fp.close()
s.close()
