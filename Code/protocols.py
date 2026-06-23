import hashlib, config
from functools import lru_cache

class UEState:
    IDLE = "IDLE"
    DISCOVERING = "DISCOVERING"       # Step 1: Sending Discovery
    DISCOVERED = "DISCOVERED"         # Step 2: Received Discovery, sending Request
    AUTHENTICATING = "AUTHENTICATING" # Step 3: Security procedure in progress, recived direct security command
    AUTHENTICATED = "AUTHENTICATED"   # Step 4: Security procedure complete, sent direct security mode complete
    CONNECTED_L2 = "CONNECTED_L2"     # Step 5: Layer 2 Link established
    CONNECTING_L3 = "CONNECTING_L3"   # Step 6: Establishing Layer 3 Link
    CONNECTED = "CONNECTED"           # Step 7: Layer 3 Link established

class UAVState:
    IDLE = "IDLE"
    DISCOVERING = "DISCOVERING"       # Step 1: Sending Discovery message
    CONNECTED = "CONNECTED"           # Step 7: Layer 3 Link established

class Message:
    """A 3GPP-standardized PDU for Sidelink (PC5) Communication."""
    def __init__(self, time, node_id, source_id, destination_id, uav, msg_type, plane="Control", **kwargs):
        self.time = time            # SimPy timestamp
        self.node_id = node_id      # e.g., "UAV_0"
        self.source_id = source_id  # if transmitted then source_id = TX, else the source
        self.destination_id = destination_id
        self.uav = uav
        self.plane = plane          # "Control" or "User" 
        self.msg_type = msg_type    # e.g., "Discovery Announcement"
        # Initialize an empty stack structure to be filled by templates
        self.stack = {
            "Application": {},       # Service Discovery/Relay Codes
            "RRC": {},               # Connection Management
            "PDCP": {},              # Security and Reliable Delivery
            "RLC": {},               # Radio Link control (segmentation and reassembly)
            "MAC": {},               # Hardware IDs and Resource Mapping
            "PHY": {},               # Synchronization and Power
            "RX": {}                 # Holds SNR, RSRP and Distance
        }
        
@lru_cache(maxsize=None)
def node_id_to_int(node_id_str, bit24_=True):
        """
        Converts a node ID string (e.g., 'GUE_01', 'UAV_01') into a 24-bit integer or 48 bit integer
        suitable for 3GPP Layer-2 IDs.
        1. Hashes the string (SHA-256) to ensure 'GUE_01' always gives the same result.
        2. Takes the last 3 bytes (24 bits) of the hash. or 48 bits
        3. Returns the integer value.
        """
        hash_object = hashlib.sha256(node_id_str.encode())
        hex_dig = hash_object.hexdigest()
        if bit24_:
            l2_id_hex = hex_dig[-6:]
            return int(l2_id_hex, 16)
        else:
            user_id_hex = hex_dig[-12:]
            return f"0x{user_id_hex}"
        
class DiscoverAnnouncment_UE_UE_Relay(Message):
    """
    Child class specifically for 3GPP TS 24.334 Mode A Discovery.
    Encapsulates the 232-bit (29-byte) PC5_DISCOVERY payload.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, relay_service_code="0x000001",  **kwargs):
        # Initialize the parent with standard discovery descriptors
        super().__init__(
            time=sim_time, 
            node_id = node_id,
            source_id = source_id,
            destination_id = destination_id, 
            uav = uav,
            plane="Control",
            msg_type="Discovery Announcement",
            **kwargs
        )

        user_info = int(node_id_to_int(node_id, False),16)
        
        # 1. APPLICATION LAYER (ProSe Protocol Payload)
        # TS 23.304 Section 5.8.4.2 defines the fiels, Section 6.3.2.4.2 defines the message as a whole
        # TS 24.334  Section 12.2.2.x explains the different fiels in the message
        self.stack["Application"] = {
            "Protocol": "PC5-D",                                            # PC5-D Layer (ProSe Discovery Protocol)
            "Message-Type": "0x41",                                         # Binary: 01 0000 01 (Open Discovery, Relay, Model A) TS 24.334 Section 12.2.2.10
            "Relay-Service-Code": relay_service_code,                       # 24 bits, A unique identifier for the connectivity service. The Remote UE filters messages based on this code.
            "User-Info-ID": user_info,                                      # 48 bits, in out-of-coverage, this typically defaults to the Relay's 24-bit L2 ID
            "Reserved": "0x00",                                             # Reserved bits
            # MIC and UTC not required for open dicovery (only required for restricted discovery)
            # "MIC": self._generate_mic(source_node_id),                    # 32-bit Hash, A cryptographic checksum calculated using the K_D key and the message content.
            # "UTC-Counter-LSB": hex(int(real_world_time.time()) & 0xFF)    # 8-bit Replay protection
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER (TS 38.331 Section 9.1.1.4, Section 6.2.2)
            self.stack["PDCP"] = {
                "Protocol": "SL-SRB4",             # Dedicated SRB Bearer-ID for Discovery
                "SDU-Type": "Control",             # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",               # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                     # Sequence Number (increment per message)
                "Ciphering": "Disabled",           # Default: off (Default for SL-SRB4 per TS 38.331)
                "Integrity": "Disabled",           # Default: off (Default for SL-SRB4 per TS 38.331)
                "Header-Size-Bytes": 2,            # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                 # 4-bit reserved field
            }

            # 3. RLC LAYER (TS 38.322 - Radio Link Control)
            # TS 38.322, Section 4.2.1.2 (Mode: UM for Broadcast/Discovery). Section 6.2.2.3. (UMD PDU Formats) Section 6.2.3.3 (SN Config: 6-bit for SL-SRB4)
            # Operating in Unacknowledged Mode (UM) for Broadcast and since message is small it will 
            # fit in one message and hence header will not include 6 bit SN
            self.stack["RLC"] = {
                "Protocol": "UMD PDU",              # (Unacknowledged Mode Data Protocol Data Unit).
                "is_segmented": "False",           # Fits in one message (no reassembly required)
                "Mode": "UM",                      # Unacknowledged Mode (Since Broadcast type)
                "Entity-Type": "TX",               # Transmitting Entity
                "SI": "00",                        # Segmentation Info: 00 = Complete PDU (Not segmentation)
                "SN": "None",                      # Sequence Number (SN): 6 bits (Configured for SL-SRB4) Only present if 'SI' != 00 (i.e., message is segmented).
                "SO": "None",                      # Segment Offset (SO): 16 bits, Only present in Middle (11) or Last (10) segments.
                "Reserved": "0x00"                 # 6 bits, Header is SI(2) + R(6) = 1 Byte.     
            }

            # 4. MAC LAYER (TS 38.321 - Medium Access Control)
            # TS 38.321 Section 6.1.6 (Format of header SL-SCH MAC PDU) TS 38.321 Table 6.2.4-1 (LCID Values)
            self.stack["MAC"] = {
                "SRC": hex((user_info>>8)&0xFFFF), # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((0xFFFFFF>>16)&0xFF),   # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                       # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "58",                      # LCID: Logical Channel ID (6 bits), Value 58 (111010) = SCCH (Discovery) per Table 6.2.4-1
                "Reserved": "0x00"                 # 1 bit reserved
            }

            # 5. PHY LAYER (TS 38.211 / 38.212 - Physical Layer) PHY_SCI
            # TS 38.212 Clause 8.3.1.1 (SCI Format 1-A - 1st Stage), TS 38.212 Clause 8.4.1.1 (SCI Format 2-A - 2nd Stage)
            self.stack["PHY"] = {
                "Channels": {"PSCCH","PSSCH"},  #PSCCH: Carries 1st Stage SCI, PSSCH: Carries 2nd Stage SCI + MAC PDU (Data)
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",                      # 3 bits (QoS), highest priority for discovery
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "00",                                                      # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(user_info&0xFF),                                       # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(0xFFFFFF&0xFFFF),                                 # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Disabled"                                             # Broadcast has no HARQ
                }
            }

class DiscoverAnnouncment_UE_Network_Relay(Message):
    """
    Child class specifically for 3GPP TS 24.334 Mode A Discovery.
    Encapsulates the 232-bit (29-byte) PC5_DISCOVERY payload.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, relay_service_code="0x000002",  **kwargs):
        # Initialize the parent with standard discovery descriptors
        super().__init__(
            time=sim_time, 
            node_id = node_id,
            source_id = source_id,
            destination_id = destination_id, 
            uav = uav,
            plane="Control",
            msg_type="Discovery Announcement",
            **kwargs
        )

        user_info = int(node_id_to_int(node_id, False),16)
        
        # # 1. APPLICATION LAYER (ProSe Protocol Payload - TS 24.334 Table 11.2.5.1.4)
        # TS 23.304 Section 5.8.4.2, Section 6.3.2.4.2
        # TS 24.334 Section        , Section 12.2.2.51(RSC),
        self.stack["Application"] = {
            "Protocol": "PC5-D",                # PC5-D Layer (ProSe Discovery Protocol)
            "Message-Type": "0x41",             # Binary: 01 0000 01 (Open Discovery, Relay, Model A) TS 24.334 Section 12.2.2.10
            "Relay-Service-Code": relay_service_code, #24 bits, A unique identifier for the connectivity service. The Remote UE filters messages based on this code.
            "Announcer-Info": user_info,        # 48 bits, in out-of-coverage, this typically defaults to the Relay's 24-bit L2 ID
            "ProSe-Relay-UE-ID": user_info,     # 24-bit Link-layer ID, that the Remote UE must use as the Destination ID in the MAC header of the next message (Request)
            "Status-Indicator": "0x01",         # 1-bit, Setting this to 1 indicates the Relay has resources available to accept new Remote UEs.
            "Reserved": "0x00"                  # 80 bits of reserved zeros
            # "MIC": self._generate_mic(source_node_id), # 32-bit Hash, A cryptographic checksum calculated using the K_D key and the message content.
            # "UTC-Counter-LSB": hex(int(real_world_time.time()) & 0xFF) # 8-bit Replay protection
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER (TS 38.331 Section 9.1.1.4, Section 6.2.2)
            self.stack["PDCP"] = {
                "Protocol": "SL-SRB4",             # Dedicated SRB Bearer-ID for Discovery
                "SDU-Type": "Control",             # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",               # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                     # Sequence Number (increment per message)
                "Ciphering": "Disabled",           # Default: off (Default for SL-SRB4 per TS 38.331)
                "Integrity": "Disabled",           # Default: off (Default for SL-SRB4 per TS 38.331)
                "Header-Size-Bytes": 2,            # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                 # 4-bit reserved field
            }

            # 3. RLC LAYER (TS 38.322 - Radio Link Control)
            # TS 38.322, Section 4.2.1.2 (Mode: UM for Broadcast/Discovery). Section 6.2.2.3. (UMD PDU Formats) Section 6.2.3.3 (SN Config: 6-bit for SL-SRB4)
            # Operating in Unacknowledged Mode (UM) for Broadcast and since message is small it will 
            # fit in one message and hence header will not include 6 bit SN
            self.stack["RLC"] = {
                "Protocol": "UMD PDU",              # (Unacknowledged Mode Data Protocol Data Unit).
                "is_segmented": "False",           # Fits in one message (no reassembly required)
                "Mode": "UM",                      # Unacknowledged Mode (Since Broadcast type)
                "Entity-Type": "TX",               # Transmitting Entity
                "SI": "00",                        # Segmentation Info: 00 = Complete PDU (Not segmentation)
                "SN": "None",                      # Sequence Number (SN): 6 bits (Configured for SL-SRB4) Only present if 'SI' != 00 (i.e., message is segmented).
                "SO": "None",                      # Segment Offset (SO): 16 bits, Only present in Middle (11) or Last (10) segments.
                "Reserved": "0x00"                 # 6 bits, Header is SI(2) + R(6) = 1 Byte.     
            }

            # 4. MAC LAYER (TS 38.321 - Medium Access Control)
            # TS 38.321 Section 6.1.6 (Format of header SL-SCH MAC PDU) TS 38.321 Table 6.2.4-1 (LCID Values)
            self.stack["MAC"] = {
                "SRC": hex((user_info>>8)&0xFFFF), # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((0xFFFFFF>>16)&0xFF),   # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                       # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "58",                      # LCID: Logical Channel ID (6 bits), Value 58 (111010) = SCCH (Discovery) per Table 6.2.4-1
                "Reserved": "0x00"                 # 1 bit reserved
            }

            # 5. PHY LAYER (TS 38.211 / 38.212 - Physical Layer) PHY_SCI
            # TS 38.212 Clause 8.3.1.1 (SCI Format 1-A - 1st Stage), TS 38.212 Clause 8.4.1.1 (SCI Format 2-A - 2nd Stage)
            self.stack["PHY"] = {
                "Channels": {"PSCCH","PSSCH"},  #PSCCH: Carries 1st Stage SCI, PSSCH: Carries 2nd Stage SCI + MAC PDU (Data)
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",                      # 3 bits (QoS), highest priority for discovery
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "00",                                                      # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(user_info&0xFF),                                       # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(0xFFFFFF&0xFFFF),                                 # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Disabled"                                             # Broadcast has no HARQ
                }
            }

class DirectCommunicationRequest(Message):
    """
    3GPP TS 24.334 Table 11.4.2.1.1: DIRECT_COMMUNICATION_REQUEST
    Sent by Remote UE to establish a direct link with the Relay.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, relay_service_code="0x000001", **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id= source_id,
            destination_id = destination_id,
            uav=uav,
            plane="Control", 
            msg_type="Direct Communication Request",
            **kwargs
        )

        user_info = int(node_id_to_int(node_id))
        
        self.stack["Application"] = {                       # TS 23.334 Table 11.4.2.1.1
            "Protocol": "PC5-SP",
            "Message-Type": "0x01",                         # 1 byte, PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
            "Sequence-Number": "0x0000",                    # 2 bytes, Increments for each new message  2 octets [TS 24.334 12.5.1.2]
            "User-Info": user_info,                         # 3-253 bytes, provides the User Info received from upper layers identifying the user which is using this direct link [TS 24.334 12.5.1.3]
            "IP-Address-Config": "0x01",                    # 1 byte, 0x01 = IPv6 configuration options for IP address used [TS 24.33412.5.1.4]
            "Maximum-Inactivity-Period": "0xFFFFFFFF",      # 4 bytes,  maximum inactivity period of the requesting UE over the direct link [TS 24.334 12.5.1.9]
            "Nonce_1": config.NONCE_1,                      # 16 Bytes, random number generated by the sender (the Remote UE) to prevent "replay attacks" [TS 24.334 12.5.1.30]
            "UE-Security-Capabilities": "0xFFFF",           # 2 bytes,  indicate which security algorithms are supported by the UE. all bits 1 = all EEA and EIA algorithms supported [TS 24.334 12.5.1.22]
            "MSB-of-KD-sess-ID": "0x00",                    # 1 btye, Key Derivation Session Identity, for new connection it should be 0 [TS 24.334 12.5.1.25]
            "KD-ID": "None",                                # Optional: Key Derivation Session Identity, for new connection it should be 0  [TS 24.334 12.5.1.30]
            "Relay-Service-Code": relay_service_code,       # 4 bytes, RSC that is in the broadcast message [TS 24.334 12.5.1.17]
            "Signature": "None",                            # Optional: used where broadcast messages and need immediate trust without a handshake. IEI 22 [TS 24.334 12.5.1.33]
            "Link-Local-IPv6-Address": "None"               # Optional: IEI 3 [TS 24.334 12.5.1.5]
        }

        if not config.HEADLESS:
            # 2. PDCP LAYER (TS 38.331 Section 9.1.1.4, Section 6.2.2)
            # Configuration: Sidelink Signalling Radio Bearer 0 (SL-SRB0)
            self.stack["PDCP"] = {
                "Protocol":"SL-SRB0",                   # SL-SRB0 (Common Control) Used for PC5-S messages before security is active.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message)
                "Ciphering": "Disabled",                # Default: off (Default for SL-SRB0 per TS 38.331)
                "Integrity": "Disabled",                # Default: off (Default for SL-SRB0 per TS 38.331)
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (TS 38.322 Section 6.1.2)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte.     
            }

            # 4. MAC LAYER (TS 38.321 - Medium Access Control)
            # TS 38.321 Section 6.1.6 (Format of header SL-SCH MAC PDU) TS 38.321 Table 6.2.4-1 (LCID Values)
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "0",                                                # LCID: Logical Channel ID (6 bits), Value 0 = SCCH (not protected) per Table 6.2.4-1
                "Reserved": "0x00"
            }

            # 5. PHY LAYER (TS 38.212 / TS 38.321) PHY_SCI
            # TS 38.212 Clause 8.3.1.1 (SCI Format 1-A - 1st Stage), TS 38.212 Clause 8.4.1.1 (SCI Format 2-A - 2nd Stage)
            self.stack["PHY"] = {
                "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK
                }
            }

class DirectSecurityModeCommand(Message):
    """
    3GPP TS 24.334 Table 11.4.12A.1.1: DIRECT_SECURITY_MODE_COMMAND
    Sent by Relay to Remote UE to initiate security.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav = uav,
            plane="Control", 
            msg_type="Direct Security Mode Command",
            **kwargs
        )
        
        self.stack["Application"] = {                   # TS 23.334 Table 11.4.12A.1.1
            "Protocol": "PC5-SP",
            "Message-Type": "0x0C",                     # 1 byte, PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
            "Sequence-Number": "0x0000",                # 2 bytes: Incremented for PC5-SP [TS 24.334 12.5.1.2]
            "UE-Security-Capabilities": "0xFFFF",       # 2 bytes: Replayed from UE's Request to ensure no tampering [TS 24.334 12.5.1.22]
            "Nonce_2": config.NONCE_2,                  # 16 bytes: Generated by Relay for mutual auth [TS 24.334 12.5.1.31]
            "Chosen-Algorithms": "0x02",                # 1 byte: Bits 5-8: 128-NEA2 (Ciphering), Bits 1-4: 128-NIA2 (Integrity) [TS 24.334 12.5.1.23]
            "MSB-of-KD-sess-ID": config.KID_MSB,            # 1 byte: Least Significant Bits of the Key Derivation Session ID [TS 24.334 12.5.1.24]
            "GPI": "None",                              # GBA (Generic Bootstrapping Architecture) Push Info: Optional IEI 11 [TS 24.334 12.5.1.18]
            "KD-Freshness": "None",                     # Optional: Used for key freshness updates [TS 24.334 12.5.1.30]
            "User-Info": "None",                        # Optional: IEI 21 [TS 24.334 12.5.1.3]
            "Signature": "None",                        # Optional: IEI 22 [TS 24.334 12.5.1.33]
            "Encrypted-Payload": "None"                 # Optional: IEI 23 [TS 24.334 12.5.1.34]
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER (TS 38.331 Section 9.1.1.4, Section 6.2.2)
            # Configuration: Sidelink Signalling Radio Bearer 0 (SL-SRB0)
            self.stack["PDCP"] = {
                "Protocol":"SL-SRB0",                   # SL-SRB0 (Common Control) Used for PC5-S messages before security is active.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x002",                          # Sequence Number (increment per message)
                "Ciphering": "Disabled",                # Default: off (Default for SL-SRB0 per TS 38.331)
                "Integrity": "Disabled",                # Default: off (Default for SL-SRB0 per TS 38.331)
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (TS 38.322) - Acknowledged Mode
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0002",                         # RLC Sequence Number
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte.     
            }

            # 4. MAC LAYER (TS 38.321)
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "1",                                                # LCID: Logical Channel ID (6 bits), Value 1 = SCCH (Direct Security Mode Command) per Table 6.2.4-1                       
                "Reserved": "0x00",
            }

            # 5. PHY LAYER (TS 38.212) PHY_SCI
            self.stack["PHY"] = {
                "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK     
                }
            }


class DirectSecurityModeComplete(Message):
    """
    3GPP TS 24.334 Table 11.4.13.1.1: DIRECT_SECURITY_MODE_COMPLETE
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav = uav,
            plane="Control", 
            msg_type="Direct Security Mode Complete",
            **kwargs
        )
        
        self.stack["Application"] = {                                   # TS 23.334 Table 11.4.13.1
            "Protocol": "PC5-SP",
            "Message-Type": "0x0D",                                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
            "Sequence-Number": "0x0003",                                # 2 bytes, Increments for each new message [TS 24.334 12.5.1.2]
            "LSB-of-KD-sess-ID": config.KID_LSB,                        # Combined with the MSB from the Relay, this uniquely identifies the security context.
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER (TS 38.331 Section 9.1.1.4, Section 6.2.2)
            # Configuration: Sidelink Signalling Radio Bearer 0 (SL-SRB0)
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB1",               # SL-SRB1 Used for PC5-S messages after security is active.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x003",                          # Sequence Number (increment per message)
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0003",                         # RLC Sequence Number
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte.     
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "0",                                                # LCID: Logical Channel ID (6 bits), Value 0 = SCCH (not protected) per Table 6.2.4-1
                "Reserved": "0x00"
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
                "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }


class DirectCommunicationAccept(Message):
    """
    3GPP TS 24.334 Table 11.4.3.1.1: DIRECT_COMMUNICATION_ACCEPT
    Final confirmation of the link.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav = uav,
            plane="Control",
            msg_type="Direct Communication Accept",
            **kwargs
        )
        
        self.stack["Application"] = {                   # TS 23.334 Table 11.4.3.1.1
            "Protocol": "PC5-SP",
            "Message-Type": "0x02",                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
            "Sequence-Number": "0x0004",                # 2 bytes, Increments for each new message [TS 24.334 12.5.1.2]
            "IP-Address-Config": "0x01",                # Confirming IPv6 config
            "Link-Local-IPv6-Address": uav.local_ip_address,    # Optional: Relay provides its link-local IP
            "SPS-Config": kwargs.get("sps_allocation", "None")
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) (fresh for SRB2)
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number (fresh for SRB2)
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK
                } 
            }

class RouterSolicitation(Message):
    """
    Step 6: Router Solicitation (ICMPv6 Type 133) (TS 23.304 Section 6.4.3)
    The Remote UE requests an IP configuration (IPv6 address) 
    to enable Layer 3 network routing.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id = node_id,
            source_id = source_id,
            destination_id = destination_id, 
            uav = uav,
            plane="User", 
            msg_type="Router Solicitation",
            **kwargs
        )
        
        # 1. APPLICATION LAYER (ICMPv6)
        self.stack["Application"] = {                               # TS 24.334 Section 10.4.6.4, TS 23.303 Section 5.4.4.2 
            "Protocol": "ICMPv6",
            "Type": "133",                                          # Router Solicitation
            "Code": "0",
            "Source-IP": "::",
            "Destination-IP": uav.local_ip_address,                 
            "Options": {
                "Type": "1",                                        # Source Link-Layer Address option
                "Length": "1",
                "Link-Layer-Address": node_id_to_int(node_id)       # The L2 ID of the Remote UE
            }
        }

        if not config.HEADLESS:

            # 2. PDCP LAYER (User Plane) TS 38.331
            # Note: IP traffic uses a DRB (Data Radio Bearer), not SRB (Signaling Bearer)
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-DRB1",                               # User Plane Bearer
                "SDU-Type": "IP",                  # Payload is an IP Packet
                "SN-Size": "12-bit",               # Typically 12 or 18 bit for DRBs
                "SN": "0x001",                     # Sequence Number
                "Ciphering": "Enabled",            # User data is encrypted using K_sess
                "Integrity": "Disabled",           # Integrity is usually DISABLED for high-throughput User Plane data
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"
            }

            # 3. RLC LAYER (AM Mode for reliable data) TS 38.322
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",             # Acknowledged Mode Data
                "Mode": "AM",                      # Reliable delivery for IP control packets
                "Entity-Type": "TX",
                "D/C": "1",                        # Data
                "P": "0",                          # Polling bit
                "SN": "0x0001",
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"
            }

            # 4. MAC LAYER (TS 38.321)
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),        # 16 MSB of Source L2 ID
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),  # 8 MSB of Dest L2 ID
                "V": "0x00",                                            # LCID 4 is the first index available for User Data (SL Traffic)
                "LCID": "4",                   
                "Reserved": "0x00"
            }

            # 5. PHY LAYER (TS 38.212)
            self.stack["PHY"] = {
                "Channels": {"PSCCH", "PSSCH", "PSFCH"},
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: Scheduling
                "Format-1-A": {
                    "Priority": "0x3",                      # Lower priority than Control Signaling (0x1)
                    "Frequency-Assignment": "Variable",
                    "Time-Assignment": "Variable",
                    "Resource-Reservation": "0",
                    "DMRS-Pattern": "0",
                    "MCS": "0x0A",                          # Higher MCS (e.g., 16QAM) often used for Data
                    "2nd-Stage-Format": "00",
                },
                # 2nd Stage: Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                              # Unicast
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                 # 8 LSB of Src
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),   # 16 LSB of Dst
                    "HARQ-Feedback": "Enabled"
                }
            }


class RouterAdvertisement(Message):
    """
    Step 7: Router Advertisement / DHCP Response (TS 23.304 Section 6.4.3)
    The Relay (acting as Gateway) assigns an IP to the UE. 
    This completes the L3 setup.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id = node_id,
            source_id = source_id,
            destination_id = destination_id,
            uav = uav,
            plane="User", 
            msg_type="Router Advertisement",
            **kwargs
        )
        
        assigned_ip = "0.0.0.0"
        assigned_ip = uav.connected_to[destination_id]
        
        self.stack["Application"] = {
            "Protocol": "ICMPv6",
            "Type": "134",                                      # Router Advertisement
            "Code": "0",
            "Source-IP": uav.local_ip_address,                  # Source is the Relay's Link-Local Address
            "Assigned-IP": assigned_ip
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER (User Plane) TS 38.331
            # Note: IP traffic uses a DRB (Data Radio Bearer), not SRB (Signaling Bearer)
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-DRB1",                               # User Plane Bearer
                "SDU-Type": "IP",                  # Payload is an IP Packet
                "SN-Size": "12-bit",               # Typically 12 or 18 bit for DRBs
                "SN": "0x001",                     # Sequence Number
                "Ciphering": "Enabled",            # User data is encrypted using K_sess
                "Integrity": "Disabled",           # Integrity is usually DISABLED for high-throughput User Plane data
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"
            }

            # 3. RLC LAYER (AM Mode for reliable data) TS 38.322
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",             # Acknowledged Mode Data
                "Mode": "AM",                      # Reliable delivery for IP control packets
                "Entity-Type": "TX",
                "D/C": "1",                        # Data
                "P": "0",                          # Polling bit
                "SN": "0x0001",
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"
            }

            # 4. MAC LAYER (TS 38.321)
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),        # 16 MSB of Source L2 ID
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),  # 8 MSB of Dest L2 ID
                "V": "0x00",                                            # LCID 4 is the first index available for User Data (SL Traffic)
                "LCID": "4",                   
                "Reserved": "0x00"
            }

            # 5. PHY LAYER (TS 38.212)
            self.stack["PHY"] = {
                "Channels": {"PSCCH", "PSSCH", "PSFCH"},
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: Scheduling
                "Format-1-A": {
                    "Priority": "0x3",                      # Lower priority than Control Signaling (0x1)
                    "Frequency-Assignment": "Variable",
                    "Time-Assignment": "Variable",
                    "Resource-Reservation": "0",
                    "DMRS-Pattern": "0",
                    "MCS": "0x0A",                          # Higher MCS (e.g., 16QAM) often used for Data
                    "2nd-Stage-Format": "00",
                },
                # 2nd Stage: Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                              # Unicast
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                 # 8 LSB of Src
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),   # 16 LSB of Dst
                    "HARQ-Feedback": "Enabled"
                }
            }

# class DirectCommunicationKeepAlive(Message):
#      def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
#         super().__init__(
#             time=sim_time, 
#             node_id=node_id, 
#             source_id=source_id,
#             destination_id=destination_id,
#             uav = uav,
#             plane="Control", 
#             msg_type="Direct Communication Keep Alive",
#             **kwargs
#         )
        
#         self.stack["Application"] = {
#             "Message-Type": "0x04",                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
#         }

# class DirectCommunicationKeepAliveAck(Message):
#      def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
#         super().__init__(
#             time=sim_time, 
#             node_id=node_id, 
#             source_id=source_id,
#             destination_id=destination_id,
#             uav = uav,
#             plane="Control", 
#             msg_type="Direct Communication Keep Alive Ack",
#             **kwargs
#         )
        
#         self.stack["Application"] = {
#             "Message-Type": "0x05",                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
#         }

# class DirectCommunicationRelease(Message):
#      def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
#         super().__init__(
#             time=sim_time, 
#             node_id=node_id, 
#             source_id=source_id,
#             destination_id=destination_id,
#             uav = uav,
#             plane="Control", 
#             msg_type="Direct Communication Release",
#             **kwargs
#         )
        
#         self.stack["Application"] = {
#             "Message-Type": "0x05",                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
#         }

# class DirectCommunicationReleaseAck(Message):
#      def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
#         super().__init__(
#             time=sim_time, 
#             node_id=node_id, 
#             source_id=source_id,
#             destination_id=destination_id,
#             uav = uav,
#             plane="Control", 
#             msg_type="Direct Communication Release Ack",
#             **kwargs
#         )
        
#         self.stack["Application"] = {
#             "Message-Type": "0x06",                     # PC5-SP Message Type [TS 24.334 Table 12.5.1.1]
#         }



class UAVRelayData(Message):
    """
    Represents a User Plane Data Packet (e.g., Voice, Video, Sensor Data).
    Defined in TS 38.300 Clause 16.9.2.1 (Sidelink User Plane Stack).
    
    Structure:
    [ PHY (SCI) | MAC (Src/Dst L2) | RLC (Seg) | PDCP (Cipher) | SDAP (QoS) | IP Payload ]
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs ):
        sequence_number = kwargs.get('sequence_number', 0)
        destination_ip = kwargs.get('destination_ip', "::1")
        payload_data = kwargs.get('payload_data', "NO_DATA")
        payload_type = kwargs.get('payload_type', "UDP (Generic)")
        generation_time = kwargs.get('generation_time', sim_time)
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav=uav,
            plane="User", 
            msg_type="UAV Relay Data",
            **kwargs
        )

        self.stack["Application"] = {
            "Protocol": "IPv6",                                     #  Section 16.12.2.1 ("User Plane Protocol Stack for L3 UE-to-Network Relay")
            "Version": "6",
            "Source-IP": uav.connected_to.get(node_id, "::1") if source_id != config.TX else uav.local_ip_address,
            "Destination-IP": destination_ip,                       
            "Payload-Type": payload_type,
            "Data-Seq-Num": sequence_number,
            "Payload-Size": "256 Bytes",
            "Generation-Time": generation_time
        }
        if not config.HEADLESS:
            self.stack["SDAP"] = {                                      # TS 37.324
                "Protocol": "SDAP",                                     # Service Data Adaptation Protocol, Maps the QoS Flow (IP packet) to the Data Radio Bearer (DRB).
                "SDAP-Header-Config": "Present",                        # Configured to have a header
                "RDI": "0",                                             # Reflective QoS Flow to DRB mapping Indication
                "RQI": "0",                                             # Reflective QoS Indication
                "QFI": 1,                                               # QoS Flow ID (Critical for Priority Handling)
                "Reserved": "0x00"
            }

            self.stack["PDCP"] = {              # TS 38.323
                "Bearer-Type": "SL-DRB1",       # Sidelink Data Radio Bearer 1
                "SDU-Type": "Data",             # User Plane Data
                "SN-Size": "18-bit",            # TS 38.323: 12 or 18 bits for DRBs. 18 used for high throughput.
                "SN": hex(sequence_number % 0x3FFFF), 
                "Ciphering": "Enabled",         # Payload is encrypted
                "Integrity": "Disabled",        # disabled for high-bandwidth User Plane to save processing
                "ROHC": "Enabled",              # Robust Header Compression (compressing IP headers)
                "Header-Size-Bytes": 3,         # 18-bit SN requires ~3 bytes header
            }

            self.stack["RLC"] = {               # TS 38.322
                "Protocol": "UMD PDU",          # Unacknowledged Mode Data standard for Voice/Video (Real-time)
                "Mode": "UM",                   
                "Entity-Type": "TX",            # Transmitting Entity
                "Segmentation-Info (SI)": "00", # 00 = Complete PDU (Not segmented for this sim)
                "SN": hex(sequence_number % 0x3F), # 6-bit Sequence Number for UM
                "Header-Size-Bytes": 1
            }

            self.stack["MAC"] = {                                       # TS 38.321
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),        # SRC: The L2 ID of the transmitting Node (e.g., Source UE)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),  # Even if IP Dest is Target UE, MAC Dest is the Relay "Next Hop".
                "LCID": "4",                                            # # LCID: Logical Channel ID. Values 4-19 are reserved for User Data streams.
                "Priority": "5",                                        # Lower priority than Control (1)
                "Format": "SL-SCH"                                      # Sidelink Shared Channel
            }

            self.stack["PHY"] = {               # TS 38.211 / TS 38.300\
                "Channels": {"PSSCH", "PSFCH"}, # Physical Sidelink Shared Channel
                "Format-1-A": {              # Scheduling Info
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits) TODO: fix
                    "2nd-Stage-Format": "0x0"              # 2 bits (00 = SCI Format 2-A)
                },
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK   
                }
            }

        self.stack["DATA"] = {
            "Data": payload_data
        }

class DNSQuery(Message):
    """
    Step A: DNS Query (Source UE -> Relay)
    Defined in TS 23.304 Clause 6.7.1.2.
    The Source UE sends a standard DNS Query (RFC 1035) over the User Plane (SL-DRB)
    to the Relay (acting as the DNS Server).
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        # Extract specific DNS args
        query_name = kwargs.get('query_name', 'target.user.prose') # The FQDN
        transaction_id = kwargs.get('transaction_id', 0x1234)      # To match Query/Response

        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav=uav,
            plane="User", 
            msg_type="DNS Query",
            **kwargs
        )

        # 1. APPLICATION LAYER (DNS - RFC 1035)
        # Transported over UDP/IP
        self.stack["Application"] = {
            "Protocol": "DNS (UDP)",
            "Transaction-ID": hex(transaction_id),
            "Flags": "0x0100",              # Standard Query, Recursion Desired
            "Questions": "1",
            "QNAME": query_name,            # e.g., "User_B@PublicSafety.org"
            "QTYPE": "AAAA (IPv6)",         # Requesting IPv6 Address (Type 28)
            "QCLASS": "IN (Internet)"
        }
        if not config.HEADLESS:
            # 2. TRANSPORT LAYER (UDP)
            # DNS uses Port 53
            self.stack["Transport"] = {
                "Protocol": "UDP",
                "Source-Port": "49152",         # Ephemeral Client Port
                "Destination-Port": "53"        # Standard DNS Port
            }

            # 3. IP LAYER (IPv6)
            # Source is UE, Dest is Relay (The Gateway)
            self.stack["Network"] = {
                "Protocol": "IPv6",
                "Source-IP": uav.connected_to.get(node_id, "::1") if source_id != config.TX else "::1",
                "Destination-IP": uav.local_ip_address, # Sent to the Relay
                "Next-Header": "UDP (17)"
            }

            # 4. SDAP LAYER (QoS)
            # DNS is latency-sensitive, so it might use a different QFI or the default one.
            self.stack["SDAP"] = {
                "Protocol": "SDAP",
                "QFI": "5",                     # QoS Flow ID (Non-GBR, default signaling)
                "RDI": "0",
                "RQI": "0"
            }

            self.stack["PDCP"] = {              # TS 38.323
                "Bearer-Type": "SL-DRB1",       # Sidelink Data Radio Bearer 1
                "SDU-Type": "Data",             # User Plane Data
                "SN-Size": "18-bit",            # TS 38.323: 12 or 18 bits for DRBs. 18 used for high throughput.
                "SN": "0x04", 
                "Ciphering": "Enabled",         # Payload is encrypted
                "Integrity": "Disabled",        # disabled for high-bandwidth User Plane to save processing
                "ROHC": "Enabled",              # Robust Header Compression (compressing IP headers)
                "Header-Size-Bytes": 3,         # 18-bit SN requires ~3 bytes header
            }

            self.stack["RLC"] = {               # TS 38.322
                "Protocol": "UMD PDU",          # Unacknowledged Mode Data standard for Voice/Video (Real-time)
                "Mode": "UM",                   
                "Entity-Type": "TX",            # Transmitting Entity
                "Segmentation-Info (SI)": "00", # 00 = Complete PDU (Not segmented for this sim)
                "SN": "0x04",                   # 6-bit Sequence Number for UM
                "Header-Size-Bytes": 1
            }

            self.stack["MAC"] = {                                       # TS 38.321
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),        # SRC: The L2 ID of the transmitting Node (e.g., Source UE)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),  # Even if IP Dest is Target UE, MAC Dest is the Relay "Next Hop".
                "LCID": "4",                                            # # LCID: Logical Channel ID. Values 4-19 are reserved for User Data streams.
                "Priority": "5",                                        # Lower priority than Control (1)
                "Format": "SL-SCH"                                      # Sidelink Shared Channel
            }

            self.stack["PHY"] = {               # TS 38.211 / TS 38.300\
                "Channels": {"PSSCH", "PSFCH"}, # Physical Sidelink Shared Channel
                "Format-1-A": {               # Scheduling Info
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits) TODO: fix
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK
                }
            }

class DNSResponse(Message):
    """
    Step B: DNS Response (Relay -> Source UE)
    Defined in TS 23.304 Clause 6.7.1.2.
    The Relay responds with the Target UE's IP address found in its internal mapping.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        # Extract specific DNS args
        query_name = kwargs.get('query_name', 'target.user.prose')
        transaction_id = kwargs.get('transaction_id', 0x1234)
        resolved_ip = kwargs.get('resolved_ip', '::1')

        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id,
            uav=uav,
            plane="User", 
            msg_type="DNS Response",
            **kwargs
        )
        
        # 1. APPLICATION LAYER (DNS Answer)
        self.stack["Application"] = {
            "Protocol": "DNS (UDP)",
            "Transaction-ID": hex(transaction_id),
            "Flags": "0x8180",              # Response, No Error, Recursion Available
            "Questions": "1",
            "Answers": "1",
            "QNAME": query_name,
            "NAME": query_name,
            "TYPE": "AAAA (IPv6)",
            "TTL": "300",
            "RDATA": resolved_ip            # The Target UE's IP Address
        }

        if not config.HEADLESS:
            # 2. TRANSPORT LAYER (UDP)
            self.stack["Transport"] = {
                "Protocol": "UDP",
                "Source-Port": "53",            # From Server (Relay)
                "Destination-Port": "49152"    # To Client (UE)
            }

            # 3. IP LAYER (IPv6)
            # Source is Relay, Dest is UE
            self.stack["Network"] = {
                "Protocol": "IPv6",
                "Source-IP": uav.local_ip_address,
                "Destination-IP": uav.connected_to.get(destination_id, "::1") if source_id == config.TX else "::1",
                "Next-Header": "UDP (17)"
            }

            # 4. SDAP LAYER (QoS)
            # DNS is latency-sensitive, so it might use a different QFI or the default one.
            self.stack["SDAP"] = {
                "Protocol": "SDAP",
                "QFI": "5",                     # QoS Flow ID (Non-GBR, default signaling)
                "RDI": "0",
                "RQI": "0"
            }

            self.stack["PDCP"] = {              # TS 38.323
                "Bearer-Type": "SL-DRB1",       # Sidelink Data Radio Bearer 1
                "SDU-Type": "Data",             # User Plane Data
                "SN-Size": "18-bit",            # TS 38.323: 12 or 18 bits for DRBs. 18 used for high throughput.
                "SN": "0x05", 
                "Ciphering": "Enabled",         # Payload is encrypted
                "Integrity": "Disabled",        # disabled for high-bandwidth User Plane to save processing
                "ROHC": "Enabled",              # Robust Header Compression (compressing IP headers)
                "Header-Size-Bytes": 3,         # 18-bit SN requires ~3 bytes header
            }

            self.stack["RLC"] = {               # TS 38.322
                "Protocol": "UMD PDU",          # Unacknowledged Mode Data standard for Voice/Video (Real-time)
                "Mode": "UM",                   
                "Entity-Type": "TX",            # Transmitting Entity
                "Segmentation-Info (SI)": "00", # 00 = Complete PDU (Not segmented for this sim)
                "SN": "0x05",                   # 6-bit Sequence Number for UM
                "Header-Size-Bytes": 1
            }

            self.stack["MAC"] = {                                       # TS 38.321
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),        # SRC: The L2 ID of the transmitting Node (e.g., Source UE)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),  # Even if IP Dest is Target UE, MAC Dest is the Relay "Next Hop".
                "LCID": "4",                                            # # LCID: Logical Channel ID. Values 4-19 are reserved for User Data streams.
                "Priority": "5",                                        # Lower priority than Control (1)
                "Format": "SL-SCH"                                      # Sidelink Shared Channel
            }

            self.stack["PHY"] = {               # TS 38.211 / TS 38.300\
                "Channels": {"PSSCH", "PSFCH"}, # Physical Sidelink Shared Channel
                "Format-1-A": {               # Scheduling Info
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits) TODO: fix
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK
                }
            }

class StatusReport(Message):
    """
    Table 3.1: Telemetry Signalling for GUE-to-UAV Status Reporting.
    Sent periodically by the GUE on its dedicated SL-SRB slot.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Status Report", 
            **kwargs
        )

        self.stack["Application"] = {
            "Message-Type": "0x00",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "Timestamp": kwargs.get("timestamp", f"{sim_time} ms"),
            "Latitude": kwargs.get("lat", "Unknown"),
            "Longitude": kwargs.get("lon", "Unknown"),
            "Altitude": kwargs.get("alt", "0 m"),
            "Accuracy": kwargs.get("accuracy", "5m"),
            "S-RSRP": kwargs.get("s_rsrp", "-80 dBm"),
            "S-RSSI": kwargs.get("s_rssi", "-75 dBm"),
            "CQI": kwargs.get("cqi", "15"),
            "PER": kwargs.get("per", "0%"),
            "Spare": "0x00"
        }

        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }


class ResourceRequest(Message):
    """
    Table 3.2: Signalling for GUE-to-UAV Resource Requesting.
    Sent when the GUE has user-plane data ready for transmission.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Resource Request", 
            **kwargs
        )
        self.stack["Application"] = {
            "Message-Type": "0x01",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "Buffer-Status-Report (BSR)": kwargs.get("bsr", "0 Bytes"),
            "QoS-Class": kwargs.get("qos", "Best Effort"),
            "CQI": kwargs.get("cqi", "15"),
            "PER": kwargs.get("per", "0%"),
            "Spare": "0x00"
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }

class LinkRelease(Message):
    """
    Table 3.5: Signalling for GUE-to-UAV Connection Release.
    Explicit release sent by the GUE to gracefully terminate the connection.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Link Release", 
            **kwargs
        )
        self.stack["Application"] = {
            "Message-Type": "0x02",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "Release-Reason": kwargs.get("reason", "User Exit"),
            "Spare": "0x00"
        }

        if not config.HEADLESS:
            
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }

class ResourceGrant(Message):
    """
    Table 3.3: Signalling for UAV-to-GUE Resource Granting.
    Issued by the UAV to allocate SL-DRB resources to a GUE.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Resource Grant", 
            **kwargs
        )
        self.stack["Application"] = {
            "Message-Type": "0x04",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "Grant-Type": kwargs.get("grant_type", "Aperiodic"),
            "Resource-Index": kwargs.get("resource_index", "Ch: 0, Slot: 0"),
            "MCS-Index": kwargs.get("mcs", "5"),
            "Grant-Timer": kwargs.get("timer", "10 subframes"),
            "Periodicity": kwargs.get("periodicity", "0 (None)"),
            "Spare": "0x00"
        }
        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }

class ReleaseACK(Message):
    """
    Table 3.6: Signalling for UAV-to-GUE Connection Release Acknowledgement.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Release ACK", 
            **kwargs
        )
        self.stack["Application"] = {
            "Message-Type": "0x08",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "Spare": "0x00"
        }
        
        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }

class DataACK(Message):
    """
    Table 3.4: Signalling for UAV-to-GUE Data Acknowledgement (Block ACK).
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="Data ACK", 
            **kwargs
        )
        self.stack["Application"] = {
            "Message-Type": "0x0F",
            "Sequence-Number": kwargs.get("seq_num", "0x0001"),
            "ACK-SN": kwargs.get("ack_sn", "0x0000"),
            "Reception-Bitmap": kwargs.get("bitmap", "11111111..."),
            "Spare": "0x00"
        }
        
        if not config.HEADLESS:
            # 2. PDCP LAYER
            self.stack["PDCP"] = {
                "Bearer-Type": "SL-SRB2",               # SL-SRB2 Used for PC5-S messages after connection is established.
                "SDU-Type": "Control",                  # SDU Type: Control Plane Data (PC5-D) there is no "SDU Type" field for SRBs; the PDU type is implicit
                "SN-Size": "12-bit",                    # (SN = Sequence number) TS 38.331 Section 9.1.1.4: pdcp-SN-Size = len12bits
                "SN": "0x001",                          # Sequence Number (increment per message) 
                "Ciphering": "Enabled",                 # Ciphering starts here
                "Integrity": "Enabled",                 # Enabled from this message onwards
                "Header-Size-Bytes": 2,                 # 12-bit SN + 4 reserved bits = 2 bytes (16 bits)
                "Reserved": "0x00"                      # 4-bit reserved field
            }

            # 3. RLC LAYER (AM Mode)
            self.stack["RLC"] = {
                "Protocol": "AMD PDU",                  # Acknowledged Mode Data
                "Mode": "AM",                           # Mode: Acknowledged Mode (AM) for reliable unicast delivery
                "Entity-Type": "TX",                    # Transmitting Entity
                "D/C": "1",                             # Data/Control PDU
                "P": "1",                               # Polling bit enabled (Requesting Status Report)
                "SN": "0x0001",                         # RLC Sequence Number 
                "Header-Size-Bytes": 2,
                "Reserved": "0x00"                      # 6 bits, Header is SI(2) + R(6) = 1 Byte. 
            }

            # 4. MAC LAYER
            self.stack["MAC"] = {
                "SRC": hex((node_id_to_int(node_id)>>8)&0xFFFF),            # SRC: Source Layer-2 ID (16 MSB) The remaining 8 LSBs are carried in the PHY SCI (Layer-1 ID)
                "DST": hex((node_id_to_int(destination_id)>>16)&0xFF),      # 24-bit Destination ID (Broadcast) The remaining 16 LSBs are carried in the PHY SCI
                "V": "0x00",                                                # V: Version (4 bits). "0000" for standard NR Sidelink
                "LCID": "2",                                                # LCID: Logical Channel ID (6 bits), Value 2 = SCCH (protected) per Table 6.2.4-1
                "Reserved": "0x00"   
            }

            # 5. PHY LAYER PHY_SCI
            self.stack["PHY"] = {
            "Channels": {"PSCCH", "PSSCH", "PSFCH"},   # PSFCH (Physical Sidelink Feedback Channel): for the ACK or NACK
                # PSCCH (Physical Sidelink Control Channel): carries SCI Format 1-A (Stage 1), PSSCH (Physical Sidelink Shared Channel): carries the SCI Format 2-A (Stage 2 control info) and the MAC PDU, 
                # --- Sidelink Control Information (SCI) ---
                # 1st Stage: SCI Format 1-A (TS 38.212 Clause 8.3.1.1)
                # Used for Scheduling PSSCH and 2nd Stage SCI
                "Format-1-A": {
                    "Priority": "0x1",
                    "Frequency-Assignment": "Variable",     # Location in Frequency
                    "Time-Assignment": "Variable",          # Location in Time
                    "Resource-Reservation": "0",            # Periodic reservation (if used)
                    "DMRS-Pattern": "0",                    # Reference Signal Config
                    "MCS": "0x05",                          # Modulation & Coding (5 bits)
                    "2nd-Stage-Format": "0x0" ,             # 2 bits (00 = SCI Format 2-A)
                },
                # 2nd Stage: SCI Format 2-A (TS 38.212 Clause 8.4.1.1)
                # Used for Decoding & Identification
                "Format-2-A": {
                    "Cast-Type": "10",                                                     # 2 bits (00=Broadcast, 01=Group, 10=Uni)
                    "Source-ID": hex(node_id_to_int(node_id)&0xFF),                        # 8 bits (LSB of Src L2 ID)
                    "Destination-ID": hex(node_id_to_int(destination_id)&0xFFFF),          # 16 bits (LSB of Dst L2 ID)
                    "HARQ-Feedback": "Enabled"                                             # Unicast requires ACK 
                }
            }

#### ----- U2N messgaes -----

class SystemInformationBroadcast(Message):
    """
    Step 1: 3GPP TS 38.331 Section 5.2.
    gNB continuously broadcasts MIB and SIBs so the UAV can sync to the network.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="System Information Broadcast", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "MIB / SIB1",
            "Cell-ID": "0x1A2B3C",
            "PLMN-IdentityList": "Public Safety Network",
            "ProSe-Relay-Supported": "True"  # gNB indicates it supports L3 Relays
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "None", "Ciphering": "Disabled", "Integrity": "Disabled"}
            self.stack["RLC"] = {"Protocol": "TM PDU", "Mode": "TM"}
            self.stack["MAC"] = {"Logical-Channel": "BCCH", "Transport-Channel": "BCH"}
            self.stack["PHY"] = {"Physical-Channel": "PBCH / PDSCH"}


class RRCSetupRequest(Message):
    """
    Step 2: 3GPP TS 38.331 Section 5.3.3. 
    UAV requests connection to the Terrestrial Network (gNB) via Uu interface.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, 
            node_id=node_id, 
            source_id=source_id,
            destination_id=destination_id, 
            uav=uav,
            plane="Control", 
            msg_type="RRC Setup Request",
            **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "RRCSetupRequest",
            "Establishment-Cause": "mo-Signalling",
            "UE-Identity": hex(node_id_to_int(node_id) & 0xFFFFFF) # Random value for initial contention
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB0", "Ciphering": "Disabled", "Integrity": "Disabled"}
            self.stack["RLC"] = {"Protocol": "TM PDU", "Mode": "TM"} # Transparent Mode
            self.stack["MAC"] = {"Logical-Channel": "CCCH"}          # Common Control Channel
            self.stack["PHY"] = {"Physical-Channel": "PRACH/PUSCH"}  # Random Access

class RRCSetup(Message):
    """
    Step 3: 3GPP TS 38.331 Section 5.3.3. 
    gNB responds establishing SRB1.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="RRC Setup", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "RRCSetup",
            "Radio-Bearer-Config": "SRB1 Established",
            "Master-Cell-Group": "Configured"
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB0", "Ciphering": "Disabled", "Integrity": "Disabled"}
            self.stack["RLC"] = {"Protocol": "TM PDU", "Mode": "TM"}
            self.stack["MAC"] = {"Logical-Channel": "CCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PDSCH"} # Downlink Shared

class RRCSetupComplete(Message):
    """
    Step 4: 3GPP TS 38.331 Section 5.3.3.
    UAV confirms parameters. CRITICAL: It encapsulates the initial NAS Registration Request.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="RRC Setup Complete", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "RRCSetupComplete",
            "Selected-PLMN": "Public Safety Network",
            "Dedicated-NAS-Message": {
                "Protocol": "NAS (5GMM)",
                "Message-Type": "Registration Request",
                "ProSe-Capability": "L3 Relay Supported"
            }
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}          # Dedicated Control Channel
            self.stack["PHY"] = {"Physical-Channel": "PUSCH"}

class SecurityModeCommand(Message):
    """
    Step 5: 3GPP TS 38.331 Section 5.3.4.
    gNB activates AS security (Ciphering and Integrity Protection).
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="Security Mode Command", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "SecurityModeCommand",
            "Security-Algorithm-Config": {
                "Ciphering": "128-NEA2",
                "Integrity": "128-NIA2"
            }
        }
        if not config.HEADLESS:
            # Integrity is applied to this message, ciphering starts immediately after
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Disabled", "Integrity": "Enabled"} 
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PDSCH"}

class SecurityModeComplete(Message):
    """
    Step 6: 3GPP TS 38.331 Section 5.3.4.
    UAV confirms AS security. All subsequent messages are encrypted.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="Security Mode Complete", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "SecurityModeComplete"
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PUSCH"}

class PDUSessionEstablishmentRequest(Message):
    """
    Step 7: 3GPP TS 38.331 Section 5.7.2.
    UAV requests an IP Prefix from Core Network to act as a Relay. 
    NAS message is encapsulated in an RRC ULInformationTransfer.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="PDU Request", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "ULInformationTransfer",
            "Dedicated-NAS-Message": {
                "Protocol": "NAS (5GSM)",  
                "Message-Type": "PDU Session Establishment Request",
                "Request-Type": "Initial request",
                "PDU-Session-Type": "IPv6",
                "Relay-Type": "Layer 3 UE-to-Network",
                "DNN": "prose.publicsafety"
            }
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PUSCH"}

class RRCReconfiguration(Message):
    """
    Step 8: 3GPP TS 38.331 Section 5.3.5.
    gNB sets up the Data Radio Bearers (DRB) for the Relay traffic.
    CRITICAL: It simultaneously delivers the NAS PDU Accept from the Core Network.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="RRC Reconfig", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "RRCReconfiguration",
            "Radio-Bearer-Config": "DRB1 Established (Relay Traffic)",
            "SRB2-Config": "SRB2 Established",
            "Dedicated-NAS-Message": {
                "Protocol": "NAS (5GSM)",
                "Message-Type": "PDU Session Establishment Accept",
                "Allocated-IP": uav.local_ip_address if hasattr(uav, 'local_ip_address') else "::1",
                "Delegated-IPv6-Prefix": config.IP_PREFIX if hasattr(config, 'IP_PREFIX') else "2001:db8::/64"
            }
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PDSCH"}

class RRCReconfigurationComplete(Message):
    """
    Step 9: 3GPP TS 38.331 Section 5.3.5.
    UAV confirms that the Uu Data Radio Bearers for the relay connection are active.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="RRC Reconfig Complete", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "RRCReconfigurationComplete"
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB1", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PUSCH"}

class RemoteUEReport(Message):
    """
    Step 11: 3GPP TS 24.501.
    Relay UE (UAV) informs Core Network about a newly connected Remote UE.
    Sent over SRB2 as it is a standard NAS message occurring post-setup.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="UE Report", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "ULInformationTransfer",
            "Dedicated-NAS-Message": {
                "Protocol": "NAS (5GMM)",
                "Message-Type": "Remote UE Report",
                "Remote-User-ID": hex(node_id_to_int(kwargs.get("remote_ue_id", "GUE_01"))),
                "Allocated-IP": kwargs.get("allocated_ip", "Unknown"),
                "Connection-Status": "Connected"
            }
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB2", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PUSCH"}

class RemoteUEReport_Ack(Message):
    """
    Step 12: 3GPP TS 24.501.
    Core Network acknowledges the Remote UE connection.
    """
    def __init__(self, sim_time, node_id, source_id, destination_id, uav, **kwargs):
        super().__init__(
            time=sim_time, node_id=node_id, source_id=source_id,
            destination_id=destination_id, uav=uav,
            plane="Control", msg_type="UE Report Ack", **kwargs
        )
        self.stack["RRC"] = {
            "Protocol": "RRC",
            "Message-Type": "DLInformationTransfer",
            "Dedicated-NAS-Message": {
                "Protocol": "NAS (5GMM)",
                "Message-Type": "Remote UE Report Ack",
                "Remote-User-ID": hex(node_id_to_int(kwargs.get("remote_ue_id", "GUE_01"))),
                "Status": "Authorized"
            }
        }
        if not config.HEADLESS:
            self.stack["PDCP"] = {"Bearer-Type": "SRB2", "Ciphering": "Enabled", "Integrity": "Enabled"}
            self.stack["RLC"] = {"Protocol": "AMD PDU", "Mode": "AM"}
            self.stack["MAC"] = {"Logical-Channel": "DCCH"}
            self.stack["PHY"] = {"Physical-Channel": "PDSCH"}