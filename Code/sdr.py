import math, config

class RadioChannel:
    def __init__(self):
        """
        :param frequency_hz: Carrier frequency (default 2.4 GHz)
        :param bandwidth_hz: Channel bandwidth (default 10 MHz)
        :param tx_power_dbm: Transmission power (default 23 dBm)
        """
        self.freq = config.SDR_FREQUENCY
        self.bandwidth = config.SDR_BANDWIDTH
        self.tx_power = config.TX_POWER_DBM
        self.noise_floor_dbm = -174 + 10 * math.log10(self.bandwidth)
        self.noise_figure = config.NOISE_FIGURE
        self.total_noise_dbm = self.noise_floor_dbm + self.noise_figure
        self.snr_threshold_connection = config.SNR_THRESHOLD_CONNECT
        self.snr_threshold_disconected = config.SNR_THRESHOLD_DISCONNECT 

    def get_free_space_path_loss(self, distance_m):
        """
        Standard Friis Free Space Path Loss (FSPL) formula.
        PL(dB) = 20log10(d) + 20log10(f) - 147.55
        """
        if distance_m < 1: distance_m = 1 # Prevent log(0) error
        pl = (20 * math.log10(distance_m) + 
              20 * math.log10(self.freq) - 
              147.55)
        return pl

    def get_link_metrics(self, distance_m):
        """
        Returns a dictionary with all physical layer metrics for a given distance.
        """
        path_loss = self.get_free_space_path_loss(distance_m)
        rx_power = self.tx_power - path_loss
        snr = rx_power - self.total_noise_dbm 
        return {
            "path_loss_db": path_loss,
            "rsrp_dbm": rx_power,
            "snr_db": snr
        }

    def attempt_reception(self, snr_db,): 
        """
        Determines if a packet is received based on SNR.
        """     
        return snr_db >= self.snr_threshold_connection