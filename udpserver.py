#!/usr/bin/python
import struct
import random
import sys
import socket
import re
import time

def match1(str1,str2):
	if re.match(r'%s'%str1,str2):
		return [re.match(r'%s'%str1,str2).group(1),re.match(r'%s'%str1,str2).group(2)]
	else:
		return None

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
	Flag = 2
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

	def unpackID(self,buff):
		return struct.unpack('H',buff[:2])[0]

	def unpackrname(self,buff):
		coo = [0,0,0,0,0,0]
		rname = ''
		pointer = 12
		coo[0], = struct.unpack('B',buff[pointer])
		i=0
		while coo[i] != 0 and i < 6:
			if i!= 0:
				rname += '.'
			name = struct.unpack('%dc'%coo[i],buff[(pointer+1):(pointer+coo[i]+1)])
			for x in name:
				rname += x
			pointer += coo[i]+1
			i += 1
			coo[i], = struct.unpack('B',buff[pointer])

		return  match1('(.*)(\.localdomain)',rname) or \
	    		    match1('(.*)(\.bupt\.edu\.cn)',rname) or \
	    		    [rname]

	def searchforip(self,rname):
		'''
		search dnsrelay for record
		'''
		rip = ''
		with open('dnsrelay.txt','r') as fp:
			records = fp.readlines()
			for x in records:
				col = x.strip('\r\n').split(' ')
				if len(col) >= 2:
					if col[1] == rname:
						rip = col[0]
						print 'Founded ' + 'ip:'+ rip
				else:
					pass
		if rip == '0.0.0.0':
			self.Flag = 1
		elif rip == '':
			self.Flag = 2
		else:
			self.Flag = 0
		return rip

	def __init__(self,buff):
		ID = self.unpackID(buff)
		rname = self.unpackrname(buff)
		print rname
		rip = self.searchforip(rname[0])
		print rip
		if self.Flag == 1:
			self.res = struct.pack('H',ID)
			self.res += struct.pack('!2B4H',0x81,0x83,1,0,1,0)
			self.res += self.__packrname(rname)
			self.res += struct.pack('!2HB2HIH',1,1,0,1,1,5,4)
		elif self.Flag == 0:	
			self.res = struct.pack('H',ID)
			self.res += struct.pack('!2B4H',0x81,0x80,1,1,0,0)
			self.res += self.__packrname(rname)
			self.res += struct.pack('!5HIH',1,1,0xc00c,1,1,5,4)
			tip = rip.split('.')
			for x in tip:
				self.res += struct.pack('B',int(x))

'''
UDP SERVER
'''
class udpserver(object):
	HOST = ''
	PORT = 53
	HOST2 = '8.8.8.8'
	def __init__(self):
		try:
			s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			s.bind((self.HOST, self.PORT))
		except socket.error,msg:
			print 'Failed to create socket.Error code: ' + str(msg[0]) + 'Error message:' + str(msg[1])
			sys.exit()
		print 'server is now waiting'
		buff, addr = s.recvfrom(1024)
		dnss = dnshandler(buff)
		res = dnss.res
		if dnss.Flag == 0:
			s.sendto(res,addr)
		elif dnss.Flag == 1:
			s.sendto(res,addr)
		elif dnss.Flag == 2:
			s.sendto(buff,(self.HOST2,self.PORT))
			buff, addr2= s.recvfrom(1024)
			s.sendto(buff,addr)
		else:
			pass
		s.close()

if __name__ == '__main__':
	while 1:
		udpserver()