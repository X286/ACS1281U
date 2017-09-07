from smartcard.System import readers #HiAPI card work
import smartcard.util as utils
from Crypto.Cipher import DES3
import os
'''
    How to see current reader you work - in terminal print pcsc_scan
    1 Step - Create Connect get number of readers in readerGroup.listofReaders
    1.1 Step - Write To Reader Some KEYZ currentreader.writeToReader
    2 Step - auth - read MC card - first auth currentreader.auth
    3 Step - read - memorySegment 3sectors for 16 bytes for info last - KEY currentreader.readBlock
    4 Step - Write - To update info blocks call reader.UpdateBlock
    5 Step Optional - To update Keys Use currentReader.UpdateKEYBlock
    appendix
    WordsToHexSRT - lambda to convert ex  bublz = r1.WordsToHexSRT ('Sepultura')
    HexSTRtoWords - lambda to convert ex  rubulz = r1.HexSTRtoWords (bublz)
'''
class ACS1281U (object): #test only for that model sorry i no have money to buy many readerz
    def __init__(self, reader):
        self.WordsToHexSRT = lambda (a) :a.encode('hex')
        self.HexSTRtoWords = lambda (a) :a.decode('hex')
        self.listofReaders = readers()
        self.currentreader = self.listofReaders [reader] #current reader for read
        self.connectToCurrentReader = self.currentreader.createConnection() #create Conn

    def cardwait (self):
        try:
            self.connectToCurrentReader.connect() #Connect
            return True
        except: return False

    def commandToReader (self, bytearray, ToHex = True):
        #  transmit to reader, ToHex - just for comfortable reading, default - TRUE convert to Hex
        print '-> To Reader', utils.toHexString(bytearray)
        readeranswer, sw1, sw2 = self.connectToCurrentReader.transmit (bytearray)
        if (ToHex):
            return utils.toHexString(readeranswer), self.convertToHex(sw1,sw2)
        else:
            return readeranswer,  sw1, sw2

    def UpdateBlock (self, blockNumber,UpData):
        cmdPrepare = 'ffd600'+blockNumber+'10'+UpData
        cmdPrepare = utils.toBytes(cmdPrepare)
        return self.commandToReader(cmdPrepare)

    def readBlock (self, Block):
        cmdPrepare = 'ffb000'+Block+'10' #firstBlocks
        cmdPrepare = utils.toBytes(cmdPrepare)
        return self.commandToReader(cmdPrepare)

    def convertToHex (self,*agw): # To Hex answer
        hexStr = ''
        for swN in agw:
            hexStr += hex(swN)+' '
        return hexStr

    def ATR (self): #ATR in HEX
        return 'ATR :' + utils.toHexString(self.connectToCurrentReader.getATR())

    def CardUID (self): #UID current card
        answer = self.commandToReader([0xFF,0xCA,0x00,0x00,0x00])
        return 'ID: '+ answer[0]

class MifareUC (ACS1281U):
     def __init__ (self, reader): #int courrent reader in list
        super (MifareUC, self).__init__(reader)

     def auth3DES (self, key):
         randA = os.urandom(8)
         getcryptedB = self.commandToReader([0xff,0x00,0x00,0x00,0x02,0x1a,0x00],ToHex=False)
         firstresponce = getcryptedB[0][1:]
         iv = '\x00\x00\x00\x00\x00\x00\x00\x00'
         zdesdec = DES3.new(key,DES3.MODE_CBC, iv)
         encryptedresp = zdesdec.decrypt(utils.HexListToBinString(firstresponce))
         rotatebytes = encryptedresp[1:]+encryptedresp[0]
         sendstr = randA+rotatebytes
         encrypt3DES = DES3.new(key,DES3.MODE_CBC,utils.HexListToBinString(firstresponce))
         responce = '\xff\x00\x00\x00\x11\xaf'+encrypt3DES.encrypt(sendstr)
         getresp = self.commandToReader(utils.BinStringToHexList(responce))

         if getresp[0]!= '00':
             return True
         else:
             return False

     def writeKey (self,key): # in one for, im too lazy for that
         keyA,keyB = key[0:8][::-1], key[8:16][::-1]
         cout = 0
         for k in range (0x2c, 0x2e, 0x01):
             writepeice = [0xff,0xd6,0x00,k,0x04]
             print utils.toHexString()
             self.commandToReader(writepeice+ utils.BinStringToHexList(keyA[cout:cout+4]))
             cout +=4
         cout = 0
         for k in range (0x2e, 0x30, 0x01):
             writepeice = [0xff,0xd6,0x00,k,0x04]
             self.commandToReader(writepeice+ utils.BinStringToHexList(keyB[cout:cout+4]))
             cout +=4
         print 'Card KEY Change'

class MifareC(ACS1281U):

    def __init__ (self, reader): #int courrent reader in list

        super (MifareC, self).__init__(reader)

    def auth (self, blockCard, KEYAorB, ReaderMem):
        cmdPrepare = 'ff860000050100'+blockCard+KEYAorB+ReaderMem
        cmdPrepare = utils.toBytes(cmdPrepare)
        return self.commandToReader(cmdPrepare)

    def writeToReader (self,WriteToMem,KeyLocation,KeyNumber):  #WriteToMem - 00 RAM, other - to ROM
        cmdPrepare = 'ff82'+WriteToMem+KeyLocation+'06'+KeyNumber
        cmdPrepare = utils.toBytes(cmdPrepare)
        return  self.commandToReader(cmdPrepare)

    def UpdateKEYBlock (self, block, KEYA, KEYB): #oldkey - get from readBlock ()
        readedMCBlock = self.readBlock(block)[0]
        getOldKeyB  = readedMCBlock.replace (" ", '')[0:12]
        getOldKeyA  = readedMCBlock.replace (" ", '')[20:]
        getLockByte = readedMCBlock.replace (" ", '')[12:20]
        print 'Old Keys:', getOldKeyB, getLockByte ,getOldKeyA
        cmdPrepare = 'ffd600'+block+'10'+KEYB+getLockByte+KEYA
        cmdPrepare = utils.toBytes(cmdPrepare)
        return self.commandToReader(cmdPrepare)