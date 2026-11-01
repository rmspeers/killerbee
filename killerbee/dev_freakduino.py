'''
Support from the Freakduino platform from Abika/Freaklabs.

This is not a maintained platfrom and functionality may be broken or lacking.
'''

import serial # type: ignore
import time
import struct
from datetime import datetime, date, timezone
from datetime import time as dttime
from .kbutils import KBCapabilities, makeFCS # type: ignore

MODE_NONE    = 0x01
MODE_SNIFF   = 0x02

class FREAKDUINO:
    def __init__(self, serialpath):
        '''
        Instantiates the KillerBee class for our sketch running on ChibiArduino on Freakduino hardware.
        @param serialpath:  /dev/ttyUSB* type serial port identifier
        @return: None
        @rtype: None
        '''
        self._channel = None
        self._page = 0
        self.handle = None
        self.dev = serialpath
        self.date = None
        self.mode = MODE_NONE
        self.__stream_open = False
        self.lon, self.lat, self.alt = (None, None, None)
        self.handle = serial.Serial(port=self.dev, baudrate=57600, \
                                    timeout=1, bytesize=8, parity='N', stopbits=1, xonxoff=0)
        self.capabilities = KBCapabilities()
        self.__set_capabilities()

    def close(self):
        '''
        Closes the serial port. After closing, must reinitialize class again before use.
        @return: None
        @rtype: None
        '''
        self.handle.close()
        self.handle = None

    # KillerBee implements these, maybe it shouldn't and instead leave it to the driver as needed.
    # TODO deprecate these functions in favor of self.capabilities class functions
    def check_capability(self, capab):
        return self.capabilities.check(capab)
    def get_capabilities(self):
        return self.capabilities.getlist()

    def __set_capabilities(self):
        '''
        Sets the capability information for Freakdruino device based on the currently loaded sketch.
        @rtype: None
        @return: None
        '''
        #TODO have it set based on what the sketch says it can support
        self.capabilities.setcapab(KBCapabilities.FREQ_2400, True)
        self.capabilities.setcapab(KBCapabilities.SNIFF, True)
        self.capabilities.setcapab(KBCapabilities.SETCHAN, True)
        return

    def get_dev_info(self):
        '''
        Returns device information in a list identifying the device.
        @rtype: List
        @return: List of 3 strings identifying device.
        '''
        return [self.dev, "Dartmouth Freakduino", ""]

    def __send_cmd(self, cmdstr, arg=None):
        self.handle.flush()
        time.sleep(1.5) #this delay seems crucial

        self.handle.write(b"S")
        self.handle.write(cmdstr.encode("ascii"))
        if arg is not None: self.handle.write(arg.encode("ascii"))
        self.handle.write(b"\r")

        self.handle.flush()

    # Deprecated due to unreliability
    def __serial_cmd(self, cmdstr, arg=None):
        '''
        Sends a command over the self.conn serial connection.
        Ex: If provided cmdstr = "C!N" it will send "SC!N", telling the device to turn on sniffing ("N"),
        and it expects to receive a confirmation back "&C!N" to confirm success.
        '''
        print("Flushing out of buffer:", self.handle.in_waiting)
        self.handle.reset_input_buffer()
        if len(cmdstr) > 3:
            raise Exception("Command string is less than minimum length (S%s)." % cmdstr)
        self.__send_cmd(cmdstr, arg)

        # TODO ugly and unreliable:
        # This should just wait for a & and then parse things after it,
        # however it seems sometimes you have to resend the command or something.
        print("Line:", self.handle.read_until(b"&"))
        counter = 0
        char = self.handle.read()
        while (char != b"&"):
            print(self.handle.in_waiting, "Waiting...", char)
            time.sleep(0.01)
            if (counter > 8):
                self.__send_cmd(cmdstr, arg)
                counter = 0
                print("Resend Response Line:", self.handle.read_until(b"&"))
            else: counter += 1
            char = self.handle.read()
        response = b""
        for i in range(3):
            response += self.handle.read()

        if response == cmdstr[:3].encode("ascii"):
            print("Got a response:", response, "matches", cmdstr)
            return True
        else:
            print("Invalid response:", response, cmdstr[:3])
            return False

    # Send the command for the Dartmouth-mod Freakduino to dump data logged in EEPROM
    def eeprom_dump(self):
        self.__send_cmd("C!D")

    # KillerBee expects the driver to implement this function
    def sniffer_on(self, channel=None, page=0):
        '''
        Turns the sniffer on such that pnext() will start returning observed
        data.  Will set the command mode to Air Capture if it is not already
        set.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.SNIFF)

        if channel is not None:
            self.set_channel(channel, page)

        #TODO implement mode change to start sniffer sending packets to us
        self.__send_cmd("C!N")
        self.mode = MODE_SNIFF
        self.__stream_open = True

    # KillerBee expects the driver to implement this function
    def sniffer_off(self):
        '''
        Turns the sniffer off, freeing the hardware for other functions.  It is
        not necessary to call this function before closing the interface with
        close().
        @rtype: None
        '''
        self.__send_cmd("C!F")
        self.mode = MODE_NONE
        self.__stream_open = False

    # KillerBee expects the driver to implement this function
    def set_channel(self, channel, page=0):
        '''
        Sets the radio interface to the specifid channel (limited to 2.4 GHz channels 11-26)
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.SETCHAN)

        if page:
            raise Exception('SubGHz not supported')
        if 11 <= channel <= 26:
            self._channel = channel
            #TODO actually check that it responds correctly to the request
            self.__send_cmd("C!C %d" % channel)
        else:
            raise Exception('Invalid channel')

    # KillerBee expects the driver to implement this function
    def inject(self, packet, channel=None, count=1, delay=0, page=0):
        '''
        Injects the specified packet contents.
        @type packet: Bytes
        @param packet: Packet contents to transmit, without FCS.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @type count: Integer
        @param count: Transmits a specified number of frames, def=1
        @type delay: Float
        @param delay: Delay between each frame, def=1
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.INJECT)

        if len(packet) < 1:
            raise Exception('Empty packet')
        if len(packet) > 125:                   # 127 - 2 to accommodate FCS
            raise Exception('Packet too long')

        if channel is not None:
            self.set_channel(channel, page)

        # Append two bytes to be replaced with FCS by firmware.
        packet = bytes(packet) + b"\x00\x00"

        for pnum in range(0, count):
            raise Exception('Not yet implemented')
            # Format for packet is opcode CMD_INJECT_FRAME, one-byte length,  packet data
            #TODO RZ_USB_COMMAND_EP, struct.pack("B", RZ_CMD_INJECT_FRAME) + struct.pack("B", len(packet)) + packet)
            time.sleep(delay)

    # KillerBee expects the driver to implement this function
    #TODO I suspect that if you don't call this often enough while getting frames, the serial buffer may overflow.
    def pnext(self, timeout=100):
        '''
        Returns packet data as a dictionary, else None.
        @type timeout: Integer
        @param timeout: Timeout to wait for packet reception in usec
        @rtype: List
        @return: Returns None is timeout expires and no packet received.  When a packet is received,
                 a list is returned, in the form [ String: packet contents | Bool: Valid CRC | Int: Unscaled RSSI ]
        '''
        if not self.__stream_open:
            self.sniffer_on() #start sniffing
        return self.pnext_rec(timeout)

    # Bulk of pnext implementation, but does not ensure the sniffer is on first, thus usable for EEPROM reading
    def pnext_rec(self, timeout=100):
        pdata = b""
        ldata = b""

        self.handle.timeout=timeout         # Allow pySerial to handle timeout
        startChar = self.handle.read()
        if not startChar: return None       # Sense timeout case (pySerial returns b"") and return

        # Listens for serial message of general format R!<data>;
        if startChar == b"R":               # Get packet data
            if self.handle.read() == b"!":
                x = self.handle.read()
                while (x != b";"):
                    pdata += x
                    x = self.handle.read()
        if startChar == b"L":               # Get location data
            if self.handle.read() == b"!":
                x = self.handle.read()
                while (x != b";"):
                    ldata += x
                    x = self.handle.read()
        if startChar == b"[":               # Sense when done reading from EEPROM
            if self.handle.read(40) == b"{[ DONE READING BACK ALL LOGGED DATA ]}]":
                raise StopIteration("All Data Read")

        # If location received, update our local variables:
        if ldata:
            self.processLocationUpdate(ldata)

        if not pdata:
            return None

        # Parse received data as <rssi>!<time>!<packtlen>!<frame>
        data = pdata.split(b"!", 3)
        try:
            rssi = data[0][0]               # single raw byte -> int
            frame = data[3]
            validcrc = (frame[-2:] == makeFCS(frame[:-2]))
        except (IndexError, ValueError):
            print("Error parsing stream received from device:", pdata, data)
            return None
        #Return in a nicer dictionary format, so we don't have to reference by number indicies.
        #Note that 0,1,2 indicies inserted twice for backwards compatibility.
        result = {0:frame, 1:validcrc, 2:rssi, 'bytes':frame, 'validcrc':validcrc, 'rssi':rssi}
        result['dbm'] = None #TODO calculate dBm antenna signal based on RSSI formula
        result['datetime'] = self.getCaptureDateTime(data)
        result['location'] = (self.lon, self.lat, self.alt)
        return result

    def getCaptureDateTime(self, data):
        '''
        Build a UTC datetime from the device's capture time field (data[1]), a 4-byte
        little-endian value in the format hhmmsscc (cc = centiseconds), and the last
        date received from the GPS. Falls back to the current UTC time if the device
        time is unusable.
        '''
        timestr = None
        try:
            timestr = "%08d" % (struct.unpack('<L', data[1])[0]) #in format hhmmsscc
            captime = dttime(int(timestr[:2]), int(timestr[2:4]), int(timestr[4:6]), int(timestr[6:]) * 10000)
        except (struct.error, ValueError, TypeError, IndexError):
            print("Issue with time format:", timestr, data)
            captime = None
        now = datetime.now(timezone.utc)
        if self.date is None: self.date = now.date()
        if captime is None or captime == dttime.min: captime = now.time()
        return datetime.combine(self.date, captime, tzinfo=timezone.utc)

    def processLocationUpdate(self, ldata):
        '''
        Take a location string passed from the device and update the driver's internal state of last received location.
        Format of ldata: 4-byte little-endian lon, lat, alt (signed), then date (unsigned, ddmmyy).
        '''
        self.lon, self.lat, self.alt = struct.unpack('<lll', ldata[0:12])
        datenum = struct.unpack('<L', ldata[12:16])[0]
        day, month, year = datenum // 10000, (datenum // 100) % 100, datenum % 100
        try:
            self.date = date(2000 + year, month, day)
        except ValueError:
            pass    # device has no valid GPS date yet; keep the previous one
        #TODO parse data formats (lon=-7228745 lat=4370648 alt=3800 age=63 date=70111 time=312530)
        print(self.lon, self.lat, self.alt, self.date)

    def ping(self, da, panid, sa, channel=None, page=0):
        '''
        Not yet implemented.
        @return: None
        @rtype: None
        '''
        raise Exception('Not yet implemented')

    def jammer_on(self, channel=None, page=0, method=None):
        '''
        Not yet implemented.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @type page: Integer
        @param page: Sets the subghz page, not supported on this device
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.PHYJAM)

        if channel is not None:
            self.set_channel(channel, page)

        #TODO implement
        raise Exception('Not yet implemented')

    def jammer_off(self):
        '''
        Not yet implemented.
        @return: None
        @rtype: None
        '''
        #TODO implement
        raise Exception('Not yet implemented')
