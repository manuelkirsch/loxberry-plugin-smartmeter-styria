from Cryptodome.Cipher import AES
import binascii
import serial
import datetime
import argparse
import socket
import sys
import time
import os
import configparser
import json
import requests
from lxml import html
import urllib.parse
import logging

def main(args):

    """
    Check if running in debug mode
    """
    if args.debug:
        import debugpy
        print("running in debug mode - waiting for debugger connection on {0}:{1}".format(args.debugip, args.debugport))
        debugpy.listen((args.debugip, args.debugport))
        debugpy.wait_for_client()

    """
    # Parse PlugIn config file
    """
    if not os.path.exists("REPLACEBYBASEFOLDER/config/plugins/REPLACEBYSUBFOLDER/smartmeterstyria.cfg"):
        logging.critical("Plugin configuration file missing {0}".format("REPLACEBYBASEFOLDER/config/plugins/REPLACEBYSUBFOLDER/smartmeterstyria.cfg"))
        sys.exit(-1)

    pluginconfig = configparser.ConfigParser()
    pluginconfig.read("REPLACEBYBASEFOLDER/config/plugins/REPLACEBYSUBFOLDER/smartmeterstyria.cfg")
    #pluginconfig.read(args.configfile)
    guek = pluginconfig.get('SMARTMETERSTYRIA', 'GUEK')
    enabled = pluginconfig.get('SMARTMETERSTYRIA', 'ENABLED')
    miniservername = pluginconfig.get('SMARTMETERSTYRIA', 'MINISERVER')
    virtualUDPPort = int(pluginconfig.get('SMARTMETERSTYRIA', 'UDPPORT'))


    """
    transistion from general.cfg to general.json
    """
    if miniservername.startswith("MINISERVER"):
        miniserverID = miniservername.replace("MINISERVER", "")
    
    else:
        miniserverID = miniservername
        miniservername = "MINISERVER{0}".format(miniserverID)

    """
    Check if general.json exists and Loxberry version > 2.2
    """
    lbsConfigGeneralJSON = os.path.join(Config.Loxberry("LBSCONFIG"), "general.json")
    lbsConfigGeneralCFG = os.path.join(Config.Loxberry("LBSCONFIG"), "general.cfg")

    if not os.path.exists(lbsConfigGeneralJSON):
        logging.warning("gerneral.json missing in path {0}".format(lbsConfigGeneralJSON))
        logging.warning("trying general.cfg instead {0}".format(lbsConfigGeneralCFG))

        if not os.path.exists(lbsConfigGeneralCFG):
            logging.critical("general.cfg not found in path {0}".format(lbsConfigGeneralCFG))
            sys.exit(-1)

        """
        general.cfg (legacy configuration file)
        """
        logging.info("using system configuration file {0}/general.cfg".format(Config.Loxberry("LBSCONFIG")))
        loxberryconfig = configparser.ConfigParser()
        loxberryconfig.read("{0}/general.cfg".format(Config.Loxberry("LBSCONFIG")))
        miniserverIP = loxberryconfig.get(miniservername, 'IPADDRESS')
    
    else:
        with open(lbsConfigGeneralJSON, "r") as lbsConfigGeneralJSONHandle:
            logging.info("using system configuration file {0}/general.json".format(Config.Loxberry("LBSCONFIG")))
            data = json.load(lbsConfigGeneralJSONHandle)

        # check if miniserver from plugin config exists in general.json
        if not miniserverID in data["Miniserver"].keys():
            logging.critical("Miniserver with id {0} not found general.json - please check plugin configuration".format(miniserverID))
            sys.exit(-1)

        miniserverIP = data["Miniserver"][miniserverID]["Ipaddress"]
        logging.info("Miniserver ip address: {0}".format(miniserverIP))


    """
    exit if PlugIn is not enabled
    """
    if enabled != "1":
        logging.warning("Plugin is not enabled in configuration - exiting")
        sys.exit(-1)


    """
    start new request session
    """
    #start 29 times (5 minutes)
    count = 0
    encKey = bytearray(binascii.unhexlify(guek))

    
    while count<31:
        data = read_from_usb()
        count = count+1
        #print(len(data))
        if (len(data) == 141): # ignore data if invalid length (e.g. first read after start)
            decrypt_msg(data, encKey, miniserverIP, virtualUDPPort)

    # exit with errorlevel 0
    sys.exit(0)

# _______________________________________________________________________________________

def decrypt_msg(readdata, encKey, miniserverIP, virtualUDPPort):
    #print(binascii.hexlify(bytearray(readdata)))
    LandisDataSize = 111
    LandisHDCLHeaderSize = 20

    systitle = readdata[LandisHDCLHeaderSize + 1:LandisHDCLHeaderSize + 1 + 8] # 8 bytes
    nonce = readdata[LandisHDCLHeaderSize + 13:LandisHDCLHeaderSize + 13 + 4]  # 4 bytes

    initvec = systitle + nonce
    #print(binascii.hexlify(bytearray(initvec)))
    cipher = AES.new(encKey, AES.MODE_GCM, initvec)
    #print(binascii.hexlify(bytearray(readdata[LandisHDCLHeaderSize+17:-3])))
    plaintxt = cipher.decrypt(readdata[LandisHDCLHeaderSize + 17:-3])
    #print(binascii.hexlify(bytearray(plaintxt)))

    Year = int.from_bytes(plaintxt[6:8], "big")
    Month = plaintxt[8]
    Day = plaintxt[9]
    Hour = plaintxt[11]
    Minute = plaintxt[12]
    Second = plaintxt[13]

    #L1Voltage = int.from_bytes(plaintxt[21:23], "big")
    #L2Voltage = int.from_bytes(plaintxt[24:26], "big")
    #L3Voltage = int.from_bytes(plaintxt[27:29], "big")

    #L1Current = int.from_bytes(plaintxt[30:32], "big") / 100
    #L2Current = int.from_bytes(plaintxt[33:35], "big") / 100
    #L3Current = int.from_bytes(plaintxt[36:38], "big") / 100

    Power = int.from_bytes(plaintxt[82:86], "big")
    #ImportPower = int.from_bytes(plaintxt[39:43], "big")
    #ExportPower = int.from_bytes(plaintxt[44:48], "big")

    ImportEnergy = int.from_bytes(plaintxt[43:47], "big")
    ExportEnergy = int.from_bytes(plaintxt[95:99], "big")

    jsdata = {}
    jsdata["datetime"] = datetime.datetime(Year, Month, Day, Hour, Minute, Second).isoformat()

    #jsdata["L1"] = {}
    #jsdata["L1"]["v"] = L1Voltage
    #jsdata["L1"]["a"] = L1Current

    #jsdata["L2"] = {}
    #jsdata["L2"]["v"] = L2Voltage
    #jsdata["L2"]["a"] = L2Current

    #jsdata["L3"] = {}
    #jsdata["L3"]["v"] = L3Voltage
    #jsdata["L3"]["a"] = L3Current

    jsdata["actual"] = Power
    #jsdata["actual"]["in"] = ImportPower
    #jsdata["actual"]["out"] = ExportPower

    #jsdata["total"] = {}
    jsdata["total_in"] = ImportEnergy
    jsdata["total_out"] = ExportEnergy

    sendudp(json.dumps(jsdata), miniserverIP, virtualUDPPort)
    logging.info(json.dumps(jsdata))

def read_from_usb():
    tty = serial.Serial(port='/dev/ttyS0', baudrate = 2400, parity =serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)

    data = bytearray()
    while len(data)<141:
        while tty.in_waiting > 0:
            data += tty.read()
        time.sleep(0.01)
    time.sleep(1)
    return data

def sendudp(data, destip, destport):
    # start a new connection udp connection
    connection = socket.socket(socket.AF_INET,     # Internet
                               socket.SOCK_DGRAM)  # UDP

    # send udp datagram
    res = connection.sendto(data.encode(), (destip, destport))

    # close udp connection
    connection.close()

    # check if all bytes in resultstr were sent
    if res != data.encode().__len__():
        logging.error("Sent bytes do not match - expected {0} : got {1}".format(data.__len__(), res))
        logging.critical("Packet-Payload {0}".format(data))
        sys.exit(-1)

# _______________________________________________________________________________________

class Config:
  __loxberry = {
    "LBSCONFIG": os.getenv("LBSCONFIG", os.getcwd()),
  }

  @staticmethod
  def Loxberry(name):
    return Config.__loxberry[name]

# _______________________________________________________________________________________

# parse args and call main function
print('Number of arguments:', len(sys.argv), 'arguments.')
print('Argument List:', str(sys.argv))

if __name__ == "__main__":
    """
    Parse commandline arguments
    """
    parser = argparse.ArgumentParser(description="Loxberry Smartmeter-Styria Plugin.")
    
    debugroup = parser.add_argument_group("debug")

    debugroup.add_argument("--debug", 
                        dest="debug",
                        default=False,
                        action="store_true",
                        help="enable debug mode")

    debugroup.add_argument("--debugip", 
                        dest="debugip",
                        default=socket.gethostbyname(socket.gethostname()),
                        action="store",
                        help="Local IP address to listen for debugger connections (default={0})".format(socket.gethostbyname(socket.gethostname())))

    debugroup.add_argument("--debugport", 
                        dest="debugport",
                        default=5678,
                        action="store",
                         help="TCP port to listen for debugger connections (default=5678)")
   
    
    loggroup = parser.add_argument_group("log")

    loggroup.add_argument("--logfile", 
                        dest="logfile",
                        default="smartmeterstyria.log",
                        type=str,
                        action="store",
                        help="specifies logfile path")

    loggroup = parser.add_argument_group("config")

    loggroup.add_argument("--configfile", 
                        dest="configfile",
                        default="smartmeterstyria.cfg",
                        type=str,
                        action="store",
                        help="specifies plugin configuration file path")

    args = parser.parse_args()

    """
    # logging configuration
    """
    logging.getLogger().setLevel(logging.DEBUG)
    logging.basicConfig(filename=args.logfile,
                        filemode='w', 
                        level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',)

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.NOTSET)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)
    logging.info("using plugin log file {0}".format(args.logfile))

    """
    call main function
    """
    try:
        main(args)
    except Exception as e:
        logging.critical(e, exc_info=True)
