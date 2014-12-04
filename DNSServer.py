import SocketServer
import struct
import socket as socketlib
import os
import thread
import time

def PrinttoScreen (text):
    while SinDNSServer.printlock:
        time.sleep(1)
    SinDNSServer.printlock = 1
    print text
    SinDNSServer.printlock = 0
    return
def AppendToFile(name,toip):
    while SinDNSServer.filelock:
        time.sleep(1)
    SinDNSServer.filelock = 1
    if not SinDNSServer.writtenmap.__contains__(name):
        fw = open('record.txt','a')   
        try:
            fw.write("%s//%s\n"%(name,toip))
            SinDNSServer.writtenmap[name] = toip
        finally:
            fw.close()
    SinDNSServer.filelock = 0
    
class Stack :
    # Creates an empty stack.
    def __init__( self ):
        self._theItems = list()
    # Returns True if the stack is empty or False otherwise.
    def isEmpty( self ):
        return len( self ) == 0
    # Returns the number of items in the stack.
    def __len__ ( self ):
        return len( self._theItems )
    # Returns the top item on the stack without removing it.
    def peek( self ):
        assert not self.isEmpty(), "Cannot peek at an empty stack"
        return self._theItems[-1]
    # Removes and returns the top item on the stack.
    def pop( self ):
        assert not self.isEmpty(), "Cannot pop from an empty stack"
        return self._theItems.pop()
    # Push an item onto the top of the stack.
    def push( self, item ):
        self._theItems.append( item )
        
# DNS Query
class SinDNSQuery:
        def __init__(self, data):
                i = 1
                self.name = ''
                while True:
                        d = ord(data[i])
                        if d == 0:
                                break;
                        if d < 32:
                                self.name = self.name + '.'
                        else:
                                self.name = self.name + chr(d)
                        i = i + 1
                self.querybytes = data[0:i + 1]
                (self.type, self.classify) = struct.unpack('>HH', data[i + 1:i + 5])
                self.len = i + 5
        def getbytes(self):
                return self.querybytes + struct.pack('>HH', self.type, self.classify)

# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS 
class SinDNSAnswer:
        def __init__(self, ip):
                self.name = 49164
                self.type = 1
                self.classify = 1
                self.timetolive = 190
                self.datalength = 4
                self.ip = ip
        def getbytes(self):
                res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
                s = self.ip.split('.')
                res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
                return res

# DNS frame
# must initialized by a DNS query frame
class SinDNSFrame:
        def __init__(self, data):
                (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH', data[0:12])
                self.query = SinDNSQuery(data[12:])
        def getname(self):
                return self.query.name
        def setip(self, ip):
                self.answer = SinDNSAnswer(ip)
                self.answers = 1
                self.flags = 33152
        def getbytes(self):
                res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
                res = res + self.query.getbytes()
                if self.answers != 0:
                        res = res + self.answer.getbytes()
                return res
# A UDPHandler to handle DNS query
class SinDNSUDPHandler(SocketServer.BaseRequestHandler):

        tocheck = Stack()
        
        def doublecheck():
            while 1:
                time.sleep(600)
                count = 0
                total = SinDNSUDPHandler.tocheck.__len__()
                while not SinDNSUDPHandler.tocheck.isEmpty():
                    name = SinDNSUDPHandler.tocheck.pop()
                    try:
                        newip = socketlib.getaddrinfo(name,0)[0][4][0]
                        if newip:
                            if newip != SinDNSServer.namemap[name]:
                                toip = SinDNSServer.namemap[name]
                                count += 1
                    finally:
                        PrinttoScreen('[Info] Refreshing: %d'%(SinDNSUDPHandler.tocheck.__len__()*100/total))
                PrinttoScreen('[Info] Refreshed %d Records!'%(count))
                
        def recheck (self,name):
            try:
                newip = socketlib.getaddrinfo(name,0)[0][4][0]
                if newip:
                    if newip != SinDNSServer.namemap[name]:
                        SinDNSUDPHandler.tocheck.push(name)
                        
            finally:
                thread.exit_thread()
                
        thread.start_new_thread(doublecheck,())
        def subThread(self):
                data = self.request[0].strip()
                dns = SinDNSFrame(data)
                socket = self.request[1]
                if(dns.query.type==1):
                        # If this is query a A record, then response it
                        
                        name = dns.getname();
                        toip = None
                        ifrom = "Local"
                        if SinDNSServer.namemap.__contains__(name):
                                # If have record, response it
                                # dns.setip(namemap[name])
                                # socket.sendto(dns.getbytes(), self.client_address)
                                toip = SinDNSServer.namemap[name]
                                thread.start_new_thread(self.recheck,(name,))
                                
                        elif SinDNSServer.namemap.__contains__('*'):
                                # Response default address
                                # dns.setip(namemap['*'])
                                # socket.sendto(dns.getbytes(), self.client_address)
                                toip = SinDNSServer.namemap['*']
                        else:
                                # ignore it
                                # socket.sendto(data, self.client_address)
                                # socket.getaddrinfo(name,0)
                                try:
                                        toip = socketlib.getaddrinfo(name,0)[0][4][0]
                                        ifrom = "Remote"
                                        if toip:
                                                SinDNSServer.namemap[name] = toip
                                                AppendToFile(name,toip)
                                        # print socket.getaddrinfo(name,0)
                                        
                                except Exception, e:
                                        if name:
                                                PrinttoScreen( '[Fail] For %s'%(name))
                                        
                        if toip:
                                dns.setip(toip)
                                PrinttoScreen( '[%s] %s --> %s'%(ifrom,name,toip))
                                socket.sendto(dns.getbytes(), self.client_address)
                else:
                        # If this is not query a A record, ignore it
                        socket.sendto(data, self.client_address)
        def handle(self):
             thread.start_new_thread(self.subThread,())

# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class SinDNSServer:
        writtenmap = {}
        printlock = 0
        filelock = 0
        def __init__(self, port=53):
                SinDNSServer.namemap = {}
                self.port = port
        def addname(self, name, ip):
                SinDNSServer.namemap[name] = ip
        def start(self):
                HOST, PORT = "0.0.0.0", self.port
                server = SocketServer.UDPServer((HOST, PORT), SinDNSUDPHandler)
                server.serve_forever()

# Now, test it
if __name__ == "__main__":
        sev = SinDNSServer()
        path = 'record.txt'
        if os.path.exists(path):
                with open('record.txt', 'r') as fr:
                        l = fr.readline()
                        count = 0
                        while l:
                                if l.find('//') > -1:
                                        t = l.split('//')
                                        sev.addname(t[0],t[1].strip())
                                        count += 1
                                l = fr.readline()
                        PrinttoScreen('Load Success! Load %d Records'%count)
        else:
                f = open('record.txt', 'w')
                f.close()
                PrinttoScreen('[Info] Record File Created'%count)
        sev.start() # start DNS server

