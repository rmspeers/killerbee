import struct  # type: ignore

from Crypto.Cipher import AES  # type: ignore

## Constants for packet decoding fields
# Frame Control Field
DOT154_FCF_TYPE_MASK = 0x0007  #: Frame type mask
DOT154_FCF_SEC_EN = 0x0008  #: Set for encrypted payload
DOT154_FCF_FRAME_PND = 0x0010  #: Frame pending
DOT154_FCF_ACK_REQ = 0x0020  #: ACK request
DOT154_FCF_INTRA_PAN = 0x0040  #: Intra-PAN activity
DOT154_FCF_DADDR_MASK = 0x0C00  #: Destination addressing mode mask
DOT154_FCF_VERSION_MASK = 0x3000  #: Frame version
DOT154_FCF_SADDR_MASK = 0xC000  #: Source addressing mask mode

# Frame Control Field Bit Shifts
DOT154_FCF_TYPE_MASK_SHIFT = 0  #: Frame type mask mode shift
DOT154_FCF_DADDR_MASK_SHIFT = 10  #: Destination addressing mode mask
DOT154_FCF_VERSION_MASK_SHIFT = 12  #: Frame versions mask mode shift
DOT154_FCF_SADDR_MASK_SHIFT = 14  #: Source addressing mask mode shift

# Address Mode Definitions
DOT154_FCF_ADDR_NONE = 0x0000  #: Not sure when this is used
DOT154_FCF_ADDR_SHORT = 0x0002  #: 4-byte addressing
DOT154_FCF_ADDR_EXT = 0x0003  #: 8-byte addressing

DOT154_FCF_TYPE_BEACON = 0  #: Beacon frame
DOT154_FCF_TYPE_DATA = 1  #: Data frame
DOT154_FCF_TYPE_ACK = 2  #: Acknowledgement frame
DOT154_FCF_TYPE_MACCMD = 3  #: MAC Command frame

DOT154_CRYPT_NONE = 0x00  #: No encryption, no MIC
DOT154_CRYPT_MIC32 = 0x01  #: No encryption, 32-bit MIC
DOT154_CRYPT_MIC64 = 0x02  #: No encryption, 64-bit MIC
DOT154_CRYPT_MIC128 = 0x03  #: No encryption, 128-bit MIC
DOT154_CRYPT_ENC = 0x04  #: Encryption, no MIC
DOT154_CRYPT_ENC_MIC32 = 0x05  #: Encryption, 32-bit MIC
DOT154_CRYPT_ENC_MIC64 = 0x06  #: Encryption, 64-bit MIC
DOT154_CRYPT_ENC_MIC128 = 0x07  #: Encryption, 128-bit MIC


class Dot154PacketParser:
    def __init__(self):
        """
        Instantiates the Dot154PacketParser class.
        """
        return

    def decrypt(self, packet, key):
        """
        Decrypts the specified packet using 802.15.4 AES-CCM* with security
        level ENC-MIC-64.  Returns empty bytes if decryption MIC validation
        fails.

        @type packet: Bytes
        @param packet: Packet contents.
        @type key: Bytes
        @param key: Key contents.
        @rtype: Bytes
        @return: Decrypted packet contents, empty bytes if the decrypted
        MIC fails validation.
        """

        # Retrieve the data payload from the packet contents
        encpayload = packet[-self.payloadlen(packet) :]

        if encpayload[0] != DOT154_CRYPT_ENC_MIC64:
            raise UnsupportedPacket("Unsupported security level in packet: 0x%02x." % encpayload[0])

        if len(key) != 16:
            raise BadKeyLength("Invalid key length (%d)." % len(key))

        # Encrypted content is:
        # Sec Level | 4-byte counter | Flags | Ciphertext | Encrypted 8-byte MIC
        if self.payloadlen(packet) < 15:
            raise BadPayloadLength("Payload length too short (%d)." % self.payloadlen(packet))

        nonce = self.nonce(packet)
        if not nonce:
            # Frame security is not enabled, nothing to decrypt
            return b""

        # Ciphertext C is everything after the 6-byte security header, up to
        # the trailing 8-byte encrypted MIC U.
        C = encpayload[6:-8]
        U = encpayload[-8:]

        # The additional authenticated data is the 802.15.4 header, plus the
        # security level, frame counter and flags byte.
        hdrlen = self.hdrlen(packet)
        a = packet[0 : hdrlen + 6]

        # CCM* with a 13-byte nonce (L=2) and an 8-byte MIC
        crypt = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8, assoc_len=len(a), msg_len=len(C))
        crypt.update(a)
        try:
            return crypt.decrypt_and_verify(C, U)
        except ValueError:
            # MIC check failed
            return b""

    def pktchop(self, packet):
        """
        Chops up the specified packet contents into a list of fields.  Does
        not attempt to re-order the field values for parsing.  b''.join(X) will
        reassemble original packet bytes.  Fields which may or may not be
        present (such as the Source PAN field) are empty if they are not
        present, keeping the list elements consistent, as follows:
        FCF | Seq# | DPAN | DA | SPAN | SA | [Beacon Data] | PHY Payload

        If the packet is a beacon frame, the Beacon Data field will be populated
        as a list element in the format:

        Superframe Spec | GTS Fields | Pending Addr Counts | Proto ID | Stack Profile/Profile Version | Device Capabilities | Ext PAN ID | TX Offset | Update ID

        An exception is raised if the packet contents are too short to
        decode.

        @type packet: Bytes
        @param packet: Packet contents.
        @rtype: list
        @return: Chopped contents of the 802.15.4 packet into list elements.
        """
        pktchop = [b"", b"", b"", b"", b"", b"", [], b""]

        pktchop[0] = packet[0:2]

        # Sequence number
        pktchop[1] = struct.pack(">B", packet[2])

        # Byte swap
        fcf = struct.unpack("<H", pktchop[0])[0]

        # Check if we are dealing with a beacon frame
        if (fcf & DOT154_FCF_TYPE_MASK) == DOT154_FCF_TYPE_BEACON:
            beacondata = [b""] * 10

            # 802.15.4 fields, SPAN and SA
            pktchop[4] = packet[3:5]
            pktchop[5] = packet[5:7]
            offset = 7

            # Slicing never raises, so a truncated beacon simply yields
            # shorter (or empty) trailing fields.
            for idx, size in (
                (0, 2),  # Superframe specification
                (1, 1),  # GTS data
                (2, 1),  # Pending address count
                (3, 1),  # Protocol ID
                (4, 1),  # Stack Profile version
                (5, 1),  # Capability information
                (6, 8),  # Extended PAN ID
                (7, 3),  # TX Offset
                (8, 1),
            ):  # Update ID
                beacondata[idx] = packet[offset : offset + size]
                offset += size

            pktchop[6] = beacondata

        else:
            # Not a beacon frame

            # DPAN
            pktchop[2] = packet[3:5]
            offset = 5

            # Examine the destination addressing mode
            daddr_mask = (fcf & DOT154_FCF_DADDR_MASK) >> 10

            if daddr_mask == DOT154_FCF_ADDR_EXT:
                pktchop[3] = packet[offset : offset + 8]
                offset += 8
            elif daddr_mask == DOT154_FCF_ADDR_SHORT:
                pktchop[3] = packet[offset : offset + 2]
                offset += 2

            # Examine the Intra-PAN flag
            if (fcf & DOT154_FCF_INTRA_PAN) == 0:
                pktchop[4] = packet[offset : offset + 2]
                offset += 2

            # Examine the source addressing mode
            saddr_mask = (fcf & DOT154_FCF_SADDR_MASK) >> 14

            if saddr_mask == DOT154_FCF_ADDR_EXT:
                pktchop[5] = packet[offset : offset + 8]
                offset += 8
            elif saddr_mask == DOT154_FCF_ADDR_SHORT:
                pktchop[5] = packet[offset : offset + 2]
                offset += 2

        # Append remaining payload
        if offset < len(packet):
            pktchop[7] = packet[offset:]

        return pktchop

    def hdrlen(self, packet):
        """
        Returns the length of the 802.15.4 header.
        @type packet: Bytes
        @param packet: Packet contents to evaluate for header length.
        @rtype: Int
        @return: Length of the 802.15.4 header.
        """

        # Minimum size is 11 (2 bytes FCF + 1 byte SEQ + 2 bytes DPAN +
        #  2 bytes DstAddr + 2 bytes SPAN + 2 bytes SrcAddr)
        # XXX Need to validate this logic based on specification
        if len(packet) < 9:
            raise Exception("Packet too small, %d bytes." % len(packet))

        # Start with minimum size, increase as needed based on FCF flags
        plen = 9

        # Byte swap
        fcf = struct.unpack("<H", packet[0:2])[0]

        # Examine the destination addressing mode
        if (fcf & DOT154_FCF_DADDR_MASK) >> 10 == DOT154_FCF_ADDR_EXT:
            plen += 6  # 8-byte addressing is in use, increasing addr 6 bytes

        # Examine the source addressing mode
        if (fcf & DOT154_FCF_SADDR_MASK) >> 14 == DOT154_FCF_ADDR_EXT:
            plen += 6  # 8-byte addressing is in use, increasing addr 6 bytes

        # Examine the Intra-PAN flag
        if (fcf & DOT154_FCF_INTRA_PAN) == 0:
            plen += 2  # Intra-PAN is false, source PAN 2-bytes is present

        return plen

    def payloadlen(self, packet):
        """
        Returns the length of the 802.15.4 payload.
        @type packet: Bytes
        @param packet: Packet contents to evaluate for header length.
        @rtype: Int
        @return: Length of the 802.15.4 payload.
        """
        return len(packet) - self.hdrlen(packet)

    def nonce(self, packet):
        """
        Returns the nonce of the 802.15.4 packet.  Returns empty bytes for
        unencrypted frames.
        @type packet: Bytes
        @param packet: Packet contents to evaluate for nonce.
        @rtype: Bytes
        @return: Nonce, empty when the frame is not encrypted.
        """

        # Byte swap
        fcf = struct.unpack("<H", packet[0:2])[0]

        if (fcf & DOT154_FCF_SEC_EN) == 0:
            # Packet is not encrypted
            return b""

        # Nonce formation is Src Addr || Frame Counter || Security Level
        pchop = self.pktchop(packet)

        # SA is the 5th list element, reverse it
        noncep1 = pchop[5][::-1]

        # Retrieve the data payload from the packet contents
        encpayload = packet[-self.payloadlen(packet) :]

        # First byte of encrypted payload is the security level
        noncep3 = struct.pack("<B", encpayload[0])

        # The next 4 bytes of the encrypted payload is the frame counter, rev
        noncep2 = encpayload[1:5][::-1]

        return noncep1 + noncep2 + noncep3


class UnsupportedPacket(Exception):
    pass


class BadKeyLength(Exception):
    pass


class BadPayloadLength(Exception):
    pass
