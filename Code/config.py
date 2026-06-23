# config.py
import ipaddress, secrets

# --- SIMULATION SETTINGS ---
SIM_MODE = "PROPOSED_U2N"  #{    BASELINE_U2U      PROPOSED_U2U     POSITIONING_TEST       BASELINE_U2N         PROPOSED_U2N   }
SIM_STEP = 20 
NUM_GUES = 40
HEADLESS = False

# --- VISUALIZATION & SCALING ---
METERS_PER_PIXEL = 10.0
GRID_STEP_SIZE = 50
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 800

# --- NODE DEFAULTS ---
UAV_START_ALT = 150    # Altitude in meters
UAV_COMM_RANGE = 3500  

# Initial Positions (Grid Coordinates in meters)
UAV_START_POS = (0, 0)
GUE_SPAWN_RANGE_X = (-2500, 2500)  # Min and Max X coordinates (in meters)
GUE_SPAWN_RANGE_Y = (-2500, 2500)  # Min and Max Y coordinates (in meters)
GUE_SPAWN_CENTER_X = 1500
GUE_SPAWN_CENTER_Y = 1000
GUE_SPAWN_SPREAD = 800

# --- PHYSICAL LAYER (SDR) ---
NUM_SUBCHANNELS = 10
SDR_FREQUENCY = 793e6  # Center frequency of 788 - 798 MHz (Band 14 Emergency)
SDR_BANDWIDTH = 10e6   # 10 MHz
TX_POWER_DBM = 13      # Standard LTE UE Power
NOISE_FIGURE = 9       # Receiver Noise Figure in dB

# SNR THRESHOLDS (Realistic QPSK/16QAM values)
SNR_THRESHOLD_CONNECT = 6.0         # Minimum SNR to decode a packet (dB)
SNR_THRESHOLD_DISCONNECT = 5.5      # Radio Link Failure threshold (dB)

# -- DISOCVERY CONFIGS ---
DISCOVERY_FREQUENCY = 1000
SELECTION_WINDOW_MAX = 100

# -- SECURITY KEYS --
NONCE_1 = f"0x{secrets.token_hex(16).upper()}"
NONCE_2 = f"0x{secrets.token_hex(16).upper()}"
KID_MSB = f"0x{secrets.token_hex(1).upper()}" 
KID_LSB = f"0x{secrets.token_hex(1).upper()}" 

# -- IP ADDRESS --
IP_PREFIX = "2001:db8:abcd:0012::/64"
NETWORK_IP = ipaddress.IPv6Network(IP_PREFIX)
UAV_IPV6 = ipaddress.IPv6Address(int(NETWORK_IP.network_address) | secrets.randbits(64))
GNB_IPV6 = ipaddress.IPv6Address(int(NETWORK_IP.network_address) | secrets.randbits(64)) #TODO: change this
EXTERNAL_SERVER_IP = "2001:db8:ffff::1"
IN_USE_IP_ADDR = []
UNUSED_IP_ADDR = [f"fe80::0200:00ff:fe00:{i:04x}" for i in range(1, NUM_GUES + 10)]

# --- TRAFFIC GENERATION ---
U2U_PROB_VOICE_CALL = 0.70     # 70% chance a session is a VoIP Call
U2U_PROB_DATA_BURST = 0.30     # 30% chance a session is a Text/Image burst
U2U_BURST_MIN_PACKETS = 1      # Min packets for an image/text message
U2U_BURST_MAX_PACKETS = 5      # Max packets for an image/text message
U2U_MEAN_CALL_DURATION = 60000 # 60 seconds
U2U_MEAN_IDLE_TIME = 180000    # 3 mins
U2N_PROB_VOICE_CALL = 0.40      # 40% chance a session is a VoIP Call
U2N_PROB_DATA_BURST = 0.60      # 60% chance a session is a Text/Image burst
U2N_BURST_MIN_PACKETS = 5       # Min packets for an image/text message (1.2 KB)
U2N_BURST_MAX_PACKETS = 30      # Max packets for an image/text message (7.6 KB)
U2N_MEAN_CALL_DURATION = 120000 # 2 mins
U2N_MEAN_IDLE_TIME = 120000     # 2 mins
U2N_EXTERNAL_VOICE_PROB = 0.80  # 80% of voice calls go to the internet
U2N_EXTERNAL_DATA_PROB = 0.95   # 95% of data bursts go to the internet
VOIP_INTERVAL = 20             # LTE/5G standard VoIP packet interval is 20ms
PACKET_SIZE_BYTES = 256

# --- RETRANSMISSION (HARQ) SETTINGS ---
MAX_RETRANSMISSIONS = 3    # Standard 3GPP limit for Sidelink HARQ retries
RETRANSMISSION_BACKOFF = 5 # Wait 5ms before trying to schedule a retransmission

# -- Others --
TX = "Transmitted"
DELAY_MIN = 30 # Model 2 handshake processing delay
DELAY_MAX = 70 # Model 2 handshake processing delay
DELAY_TX = 5
GRANT_TIMEOUT_APERIODIC = 100  # Max ms to wait for a data burst grant
GRANT_TIMEOUT_PERIODIC = 100   # Max ms to wait for a VoIP grant
BURST_PACKET_GAP = 10          # ms processing gap between burst packets
POLL_INTERVAL = 5              # ms to wait between checking for a grant
DNS_LOOKUP_DELAY = 10          # time for UAV to look up DNS query
DNS_SELECTION_WINDOW = 10

# -- PROPOSED CONFIG (TDD SUPER-FRAME)--
SUPER_FRAME_MS = 100         # Total duration of the control heartbeat cycle
TDD_FRAME_MS = 20            # The 5G VoIP standard TDD frame
TDD_DL_MS = 10               # First half (0-9): UAV Transmits
TDD_UL_MS = 10               # Second half (10-19): GUEs Transmit
CONTROL_CH_UAV = 0           # Ch 0 strictly for UAV Downlinks
CONTROL_CH_GUE = 1           # Ch 1 strictly for GUE Uplink control heartbeats
RESERVED_CP = 2              # Channels 0 and 1 are reserved for control
NO_OF_HEARTBEAT_MISSED = 5   # Implicit release threshold

# --- UAV MOBILITY SETTINGS ---
UAV_SPEED_M_S = 150                 # Max speed of UAV in meters per second
POSITION_UPDATE_INTERVAL = 100    # How often the UAV recalculates and moves (in ms)
UAV_MOBILITY = True

# --- U2N SETTINGS ---
GNB_POS = (-3500, 2500) # Placed far out, representing the closest operational cell tower
GNB_ALT = 50           # Standard macro-cell tower height
DELAY_BACKHAUL = 15