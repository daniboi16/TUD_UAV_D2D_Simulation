# sim_traffic.py
import math, random, secrets, config
from protocols import *
from PyQt6.QtCore import QPointF 

debug_filename = "post_setup_collision_debug.txt"

class TrafficMixin:
    """
    This class holds all the traffic generation and handling methods.
    It will be merged into SimulationEngine.
    """

    def uav_mac_layer_process(self):
        """
        Runs every 1ms. Checks if the UAV is in a valid Downlink slot (Slots 1-9).
        If yes, and there are messages in the tx_buffer, it pops and transmits one.
        Slot 0 is skipped to act as the Guard Band. But really it is from 0 to 0.5 and 9.5 to 10
        """
        while True:
            current_slot_in_frame = self.env.now % config.TDD_FRAME_MS  # Determine where we are in the 20ms TDD frame
            # Check if we are in the Downlink Phase (Slots 1 to 9): Slot 0 is intentionally skipped (Guard Time), Slots 10-19 are Uplink (GUEs transmitting)
            if 0 < current_slot_in_frame < config.TDD_DL_MS: 
                # --- 1. PROCESS CONTROL PLANE (Channel 0) --- 
                if len(self.uav.tx_buffer) > 0:     # If there are messages waiting to be sent
                    msg_params = self.uav.tx_buffer.pop(0)      # Pop the oldest message (FIFO)
                    ch = msg_params.get("subchannel", config.CONTROL_CH_UAV)
                    self.declare_tx_intent(self.env.now, ch, self.uav.id)   # Log the intent to transmit for the GUI
                    self.transmit_message(**msg_params)     # Execute the transmission
                # # --- 2. PROCESS USER PLANE (Channels 2 through 9) ---
                remaining_dl_slots = config.TDD_DL_MS - current_slot_in_frame
                if remaining_dl_slots > 0:
                    packets_to_send = math.ceil(len(self.uav.data_tx_buffer) / remaining_dl_slots)
                else:
                    packets_to_send = len(self.uav.data_tx_buffer)
                max_channels_available = config.NUM_SUBCHANNELS - config.RESERVED_CP
                packets_to_send = min(packets_to_send, max_channels_available)
                packets_sent = 0
                current_ch_idx = config.RESERVED_CP 
                while len(self.uav.data_tx_buffer) > 0 and packets_sent < packets_to_send:
                    data_msg_params = self.uav.data_tx_buffer.pop(0)
                    data_msg_params["subchannel"] = current_ch_idx
                    self.declare_tx_intent(self.env.now, current_ch_idx, self.uav.id)
                    success = self.transmit_message(**data_msg_params)
                    if not success:
                        if data_msg_params.get("payload_type", "").startswith("VoIP"):
                            self.stats["voip_packets_dropped"] += 1
                        else:
                            self.stats["data_packets_dropped"] += 1
                    current_ch_idx += 1 
                    packets_sent += 1

            yield self.env.timeout(1)   # Wait exactly 1ms to check the next slot

    def ue_traffic_generator(self, ue):
        """The Application Layer State Machine."""
        ue.app_state = "IDLE"
        yield self.env.timeout(random.randint(0, 2000)) 
        while True:
            if ue.status != UEState.CONNECTED or ue.app_state != "IDLE":
                yield self.env.timeout(random.randint(50, 150))
                continue
            available_targets = [
                t for t in self.ues 
                if t.id != ue.id and t.status == UEState.CONNECTED and getattr(t, 'app_state', 'IDLE') == "IDLE"
            ]
            if not available_targets:
                yield self.env.timeout(random.randint(50, 150))
                continue
            target_ue = random.choice(available_targets)
            ue.app_state = "SETUP"
            target_ue.app_state = "SETUP"
            # DNS Resolution
            target_ip = ue.dns_cache.get(target_ue.id)
            if not target_ip:
                yield self.env.process(self.perform_dns_resolution(ue, self.uav, target_ue))
                target_ip = ue.dns_cache.get(target_ue.id)
            if not target_ip:
                ue.app_state = "IDLE"
                target_ue.app_state = "IDLE"
                yield self.env.timeout(random.randint(50, 150))
                continue 
            # Session Decision Tree
            if random.random() < config.U2U_PROB_VOICE_CALL:
                ue.app_state = "IN_CALL"
                target_ue.app_state = "IN_CALL"
                yield self.env.process(self.simulate_voice_call(ue, target_ue, target_ip))
            else:
                ue.app_state = "SENDING_BURST"
                target_ue.app_state = "IDLE"
                yield self.env.process(self.simulate_data_burst(ue, target_ue, target_ip))
            yield self.env.timeout(random.expovariate(1.0 / config.U2U_MEAN_IDLE_TIME))

    def simulate_data_burst(self, src_ue, target_ue, target_ip):
        """Simulates sending 1 to 5 packets for an Image/Text message."""
        num_packets = random.randint(config.U2U_BURST_MIN_PACKETS, config.U2U_BURST_MAX_PACKETS)
        seq_num = random.randint(0, 1000)
        if config.SIM_MODE in ["BASELINE_U2U", "BASELINE_U2N"]:
            for i in range(num_packets):
                if src_ue.status != UEState.CONNECTED:
                    break 
                payload = secrets.token_hex(16)
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission(
                    src_ue, self.uav, target_ip, seq_num + i, payload, payload_type="Image/Text Message", max_retries=config.MAX_RETRANSMISSIONS
                ))
        elif config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"]:
            if src_ue.sps_config is None:
                src_ue.app_state = "IDLE"
                return
            # 1. Wait for our next dedicated SPS control slot
            periodicity = src_ue.sps_config['periodicity']
            offset = src_ue.sps_config['offset']
            time_in_cycle = self.env.now % periodicity
            wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
            yield self.env.timeout(wait_time)
            if src_ue.status != UEState.CONNECTED or src_ue.sps_config is None:
                src_ue.app_state = "IDLE"
                return
            # 2. Send the Resource Request on the Control Plane
            src_ue.active_grant = None
            src_ue.req_time = self.env.now
            self.declare_tx_intent(self.env.now, src_ue.sps_config['subchannel'], src_ue.id)
            self.transmit_message(
                ResourceRequest, 
                src_ue, 
                self.uav, 
                self.uav.id, 
                subchannel=src_ue.sps_config['subchannel'],
                bsr=f"{num_packets * 256} Bytes"
            )
            # 3. Wait for the UAV to issue the grant
            timeout = self.env.now + config.GRANT_TIMEOUT_APERIODIC
            while src_ue.active_grant is None and self.env.now < timeout:
                yield self.env.timeout(config.POLL_INTERVAL) 
            if src_ue.active_grant:
                # 4. We got the grant! Transmit the data burst on the granted User Plane channel
                self.stats["scheduling_delay_sum"] += (src_ue.grant_rx_time - src_ue.req_time)
                self.stats["scheduling_delay_count"] += 1
                src_ue.active_grant.sort(key=lambda g: g.get("absolute_time", 0))
                for i, grant in enumerate(src_ue.active_grant):
                    if src_ue.status != UEState.CONNECTED:
                        break
                    self.stats["total_generated_data_pkts"] += 1  
                    granted_ch = grant["subchannel"]
                    absolute_time = grant["absolute_time"]
                    wait_time = absolute_time - self.env.now
                    if wait_time > 0:
                        yield self.env.timeout(wait_time)
                    elif wait_time < 0:
                        self.stats["data_packets_dropped"] += 1
                        continue
                    payload = secrets.token_hex(16)
                    self.declare_tx_intent(self.env.now, granted_ch, src_ue.id)
                    success = self.transmit_message(
                        UAVRelayData, 
                        src_ue, 
                        self.uav, 
                        self.uav.id,
                        subchannel=granted_ch,
                        sequence_number=seq_num + i,
                        destination_ip=target_ip,
                        payload_data=payload,
                        payload_type="Image/Text Message",
                        generation_time=self.env.now
                    )
                    if not success:
                        self.stats["data_packets_dropped"] += 1
                # 5. Data burst complete, UAV sends Block ACK in the DL phase
                self.uav.tx_buffer.append({
                    "MsgClass": DataACK, 
                    "tx_node": self.uav, 
                    "rx_node": src_ue, 
                    "dest_id": src_ue.id,
                    "subchannel": config.CONTROL_CH_UAV,
                    "ack_sn": seq_num
                })
            else:
                self.stats["data_packets_dropped"] += num_packets
                self.stats["total_generated_data_pkts"] += num_packets
        src_ue.app_state = "IDLE"

    def simulate_voice_call(self, ue_a, ue_b, ip_b):
        """Simulates a persistent bi-directional VoIP session."""
        duration = random.expovariate(1.0 / config.U2U_MEAN_CALL_DURATION)
        end_time = self.env.now + duration
        seq_a = random.randint(0, 1000)
        seq_b = random.randint(0, 1000)
        ip_a = self.uav.connected_to.get(ue_a.id, "::1")
        if config.SIM_MODE in ["BASELINE_U2U", "BASELINE_U2N"]:
            while self.env.now < end_time:
                if ue_a.status != UEState.CONNECTED or ue_b.status != UEState.CONNECTED:
                    break
                # UE A talks to UE B
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission(
                    ue_a, self.uav, ip_b, seq_a, secrets.token_hex(8), payload_type="VoIP (RTP)"
                ))
                seq_a += 1
                # UE B talks to UE A
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission(
                    ue_b, self.uav, ip_a, seq_b, secrets.token_hex(8), payload_type="VoIP (RTP)"
                ))
                seq_b += 1
                # Wait standard VoIP interval before generating the next voice frame
                yield self.env.timeout(config.VOIP_INTERVAL)

        elif config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"]:
            if ue_a.sps_config is None or ue_b.sps_config is None:
                ue_a.app_state = "IDLE"
                ue_b.app_state = "IDLE"
                return
            # 1. UE A and UE B request Periodic Grants
            for ue in [ue_a, ue_b]:
                periodicity = ue.sps_config['periodicity']
                offset = ue.sps_config['offset']
                time_in_cycle = self.env.now % periodicity
                wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
                yield self.env.timeout(wait_time)
                if ue.status != UEState.CONNECTED or ue.sps_config is None:
                    continue
                ue.active_grant = None
                ue.req_time = self.env.now
                self.declare_tx_intent(self.env.now, ue.sps_config['subchannel'], ue.id)
                self.transmit_message(
                    ResourceRequest, ue, self.uav, self.uav.id,
                    subchannel=ue.sps_config['subchannel'],
                    bsr="Continuous", qos="Voice"
                )
            # 2. Wait for the UAV to issue both grants (Timeout after 100ms)
            timeout = self.env.now + config.GRANT_TIMEOUT_PERIODIC
            while (ue_a.active_grant is None or ue_b.active_grant is None) and self.env.now < timeout:
                yield self.env.timeout(config.POLL_INTERVAL)
            # 3. If grants received, transmit VoIP frames periodically
            if ue_a.active_grant and ue_b.active_grant:
                granted_ch_a = ue_a.active_grant[0]["subchannel"]
                offset_a = ue_a.active_grant[0]["offset"]
                granted_ch_b = ue_b.active_grant[0]["subchannel"]
                offset_b = ue_b.active_grant[0]["offset"]
                while self.env.now < end_time:
                    if ue_a.status != UEState.CONNECTED or ue_b.status != UEState.CONNECTED:
                        break  
                    # UE A Transmits on its exact slot
                    time_in_cycle = self.env.now % config.VOIP_INTERVAL
                    wait_time = offset_a - time_in_cycle if time_in_cycle <= offset_a else config.VOIP_INTERVAL - time_in_cycle + offset_a
                    if wait_time > 0: yield self.env.timeout(wait_time)
                    self.stats["total_generated_data_pkts"] += 1
                    self.declare_tx_intent(self.env.now, granted_ch_a, ue_a.id)
                    success_a = self.transmit_message(
                        UAVRelayData, 
                        ue_a, 
                        self.uav, 
                        self.uav.id,
                        subchannel=granted_ch_a, 
                        sequence_number=seq_a,
                        destination_ip=ip_b, 
                        payload_data=secrets.token_hex(8), 
                        payload_type="VoIP (RTP)",
                        generation_time=self.env.now
                    )
                    if not success_a:
                        self.stats["voip_packets_dropped"] += 1
                    seq_a += 1
                    # UE B Transmits on its exact slot
                    time_in_cycle = self.env.now % config.VOIP_INTERVAL
                    wait_time = offset_b - time_in_cycle if time_in_cycle <= offset_b else config.VOIP_INTERVAL - time_in_cycle + offset_b
                    if wait_time > 0: yield self.env.timeout(wait_time)
                    self.stats["total_generated_data_pkts"] += 1
                    self.declare_tx_intent(self.env.now, granted_ch_b, ue_b.id)
                    success_b = self.transmit_message(
                        UAVRelayData, 
                        ue_b, 
                        self.uav, 
                        self.uav.id,
                        subchannel=granted_ch_b, 
                        sequence_number=seq_b,
                        destination_ip=ip_a, 
                        payload_data=secrets.token_hex(8), 
                        payload_type="VoIP (RTP)",
                        generation_time=self.env.now
                    )
                    if not success_b:
                        self.stats["voip_packets_dropped"] += 1
                    seq_b += 1
                    yield self.env.timeout(1)
                # 4. Call ended! Explicitly release the periodic grants (BSR = 0)
                for ue in [ue_a, ue_b]:
                    if ue.status != UEState.CONNECTED:
                        continue
                    periodicity = ue.sps_config['periodicity']
                    offset = ue.sps_config['offset']
                    time_in_cycle = self.env.now % periodicity
                    wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
                    yield self.env.timeout(wait_time)
                    if ue.status != UEState.CONNECTED or ue.sps_config is None:
                        continue
                    self.declare_tx_intent(self.env.now, ue.sps_config['subchannel'], ue.id)
                    self.transmit_message(
                        ResourceRequest, 
                        ue, 
                        self.uav, 
                        self.uav.id,
                        subchannel=ue.sps_config['subchannel'],
                        bsr="0 Bytes", 
                        qos="Voice"
                    )
            else:
                self.stats["voip_packets_dropped"] += 1
        ue_a.app_state = "IDLE"
        ue_b.app_state = "IDLE"

    def ue_u2n_traffic_generator(self, ue):
        """The Application Layer State Machine specifically for U2N Relay scenarios."""
        ue.app_state = "IDLE"
        yield self.env.timeout(random.randint(0, 2000)) 
        while True:
            # 1. If not connected, or currently busy, wait
            if ue.status != UEState.CONNECTED or ue.app_state != "IDLE":
                yield self.env.timeout(random.randint(50, 150))
                continue
            # 2. Determine Session Type
            is_voice = random.random() < config.U2N_PROB_VOICE_CALL
            is_external = random.random() < (config.U2N_EXTERNAL_VOICE_PROB if is_voice else config.U2N_EXTERNAL_DATA_PROB)
            target_ue = None
            target_ip = None
            # 3. Target Acquisition
            if is_external:
                target_ip = config.EXTERNAL_SERVER_IP
            else:
                available_targets = [
                    t for t in self.ues 
                    if t.id != ue.id and t.status == UEState.CONNECTED and getattr(t, 'app_state', 'IDLE') == "IDLE"
                ]
                if not available_targets:
                    yield self.env.timeout(random.randint(50, 150))
                    continue
                target_ue = random.choice(available_targets)
                ue.app_state = "SETUP"
                target_ue.app_state = "SETUP"
                # DNS Resolution
                target_ip = ue.dns_cache.get(target_ue.id)
                if not target_ip:
                    yield self.env.process(self.perform_dns_resolution(ue, self.uav, target_ue))
                    target_ip = ue.dns_cache.get(target_ue.id)
                if not target_ip:
                    ue.app_state = "IDLE"
                    target_ue.app_state = "IDLE"
                    yield self.env.timeout(random.randint(50, 150)) 
                    continue 
            # 4. Session Execution
            ue.app_state = "IN_CALL" if is_voice else "SENDING_BURST"
            if is_voice:
                yield self.env.process(self.simulate_u2n_voice_call(ue, target_ue, target_ip, is_external))
            else:
                if not is_external and target_ue:
                    target_ue.app_state = "IDLE"
                yield self.env.process(self.simulate_u2n_data_burst(ue, target_ue, target_ip, is_external))
            # 5. Session over, cool down
            yield self.env.timeout(random.expovariate(1.0 / config.U2N_MEAN_IDLE_TIME))

    def simulate_u2n_data_burst(self, src_ue, target_ue, target_ip, is_external):
        """Simulates sending a burst of data. Internal = Small, External = Large."""
        if is_external:
            num_packets = random.randint(config.U2N_BURST_MIN_PACKETS, config.U2N_BURST_MAX_PACKETS)
        else:
            num_packets = random.randint(config.U2U_BURST_MIN_PACKETS, config.U2U_BURST_MAX_PACKETS) 
        seq_num = random.randint(0, 1000)
        if config.SIM_MODE == "PROPOSED_U2N":
            if src_ue.sps_config is None:
                src_ue.app_state = "IDLE"
                if not is_external: target_ue.app_state = "IDLE"
                return
            # Request Grant (Piggyback on next SPS slot)
            periodicity = src_ue.sps_config['periodicity']
            offset = src_ue.sps_config['offset']
            time_in_cycle = self.env.now % periodicity
            wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
            yield self.env.timeout(wait_time)
            if src_ue.status != UEState.CONNECTED:
                src_ue.app_state = "IDLE"
                return
            src_ue.active_grant = None
            src_ue.req_time = self.env.now
            self.declare_tx_intent(self.env.now, src_ue.sps_config['subchannel'], src_ue.id)
            self.transmit_message(
                ResourceRequest, src_ue, self.uav, self.uav.id,
                subchannel=src_ue.sps_config['subchannel'], bsr=f"{num_packets * 256} Bytes"
            )
            # Wait for Grant
            timeout = self.env.now + config.GRANT_TIMEOUT_APERIODIC
            while src_ue.active_grant is None and self.env.now < timeout:
                yield self.env.timeout(config.POLL_INTERVAL)
            if src_ue.active_grant:
                self.stats["scheduling_delay_sum"] += (src_ue.grant_rx_time - src_ue.req_time)
                self.stats["scheduling_delay_count"] += 1
                src_ue.active_grant.sort(key=lambda g: g.get("absolute_time", 0))
                for i, grant in enumerate(src_ue.active_grant):
                    if src_ue.status != UEState.CONNECTED: break
                    wait_time = grant["absolute_time"] - self.env.now
                    if wait_time > 0: yield self.env.timeout(wait_time)
                    elif wait_time < 0:
                        self.stats["data_packets_dropped"] += 1
                        continue
                    self.stats["total_generated_data_pkts"] += 1
                    self.declare_tx_intent(self.env.now, grant["subchannel"], src_ue.id)
                    success = self.transmit_message(
                        UAVRelayData, src_ue, self.uav, self.uav.id,
                        subchannel=grant["subchannel"], sequence_number=seq_num + i,
                        destination_ip=target_ip, payload_data=secrets.token_hex(16),
                        payload_type="Data Burst", generation_time=self.env.now
                    )
                    if not success: self.stats["data_packets_dropped"] += 1
                # Send ACK
                self.uav.tx_buffer.append({
                    "MsgClass": DataACK, "tx_node": self.uav, "rx_node": src_ue, 
                    "dest_id": src_ue.id, "subchannel": config.CONTROL_CH_UAV, "ack_sn": seq_num
                })
            else:
                self.stats["data_packets_dropped"] += num_packets
                self.stats["total_generated_data_pkts"] += num_packets
        elif config.SIM_MODE == "BASELINE_U2N":
            for i in range(num_packets):
                if src_ue.status != UEState.CONNECTED:
                    break 
                self.stats["total_generated_data_pkts"] += 1
                yield self.env.process(self.perform_mode_2_transmission(
                    src_ue, self.uav, target_ip, seq_num + i, secrets.token_hex(16), payload_type="Data Burst", max_retries=config.MAX_RETRANSMISSIONS
                ))
        if is_external and src_ue.status == UEState.CONNECTED:
            # The UE finished uploading its request. The external server now responds. Generate a random payload size for the server's response
            response_packets = random.randint(config.U2N_BURST_MIN_PACKETS, config.U2N_BURST_MAX_PACKETS)
            # Wait for the downlink burst to finish before unlocking the UE
            yield self.env.process(self._external_data_downlink_burst(src_ue, response_packets))
        src_ue.app_state = "IDLE"

    def simulate_u2n_voice_call(self, src_ue, target_ue, target_ip, is_external):
        """Simulates Voice Calls. Injects Downlink traffic from gNB if external."""
        duration = random.expovariate(1.0 / config.U2N_MEAN_CALL_DURATION)
        end_time = self.env.now + duration
        seq_src = random.randint(0, 1000)
        if not is_external:
            yield self.env.process(self.simulate_voice_call(src_ue, target_ue, target_ip))
            return
        # --- EXTERNAL CALL LOGIC ---
        if config.SIM_MODE == "PROPOSED_U2N":
            if src_ue.sps_config is None:
                src_ue.app_state = "IDLE"
                return
            # 1. Request Periodic Grant for the Uplink
            periodicity = src_ue.sps_config['periodicity']
            offset = src_ue.sps_config['offset']
            time_in_cycle = self.env.now % periodicity
            wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
            yield self.env.timeout(wait_time)
            src_ue.active_grant = None
            src_ue.req_time = self.env.now
            self.declare_tx_intent(self.env.now, src_ue.sps_config['subchannel'], src_ue.id)
            self.transmit_message(
                ResourceRequest, src_ue, self.uav, self.uav.id,
                subchannel=src_ue.sps_config['subchannel'], bsr="Continuous", qos="Voice"
            )
            # 2. Wait for Grant
            timeout = self.env.now + config.GRANT_TIMEOUT_PERIODIC
            while src_ue.active_grant is None and self.env.now < timeout:
                yield self.env.timeout(config.POLL_INTERVAL)
            if src_ue.active_grant:
                granted_ch = src_ue.active_grant[0]["subchannel"]
                offset_a = src_ue.active_grant[0]["offset"]
                # 3. SPUR THE EXTERNAL DOWNLINK PROCESS
                dl_process = self.env.process(self._external_voice_downlink_stream(src_ue, end_time))
                # 4. GUE Uplink Transmission Loop
                while self.env.now < end_time:
                    if src_ue.status != UEState.CONNECTED: break
                    time_in_cycle = self.env.now % config.VOIP_INTERVAL
                    wait_time = offset_a - time_in_cycle if time_in_cycle <= offset_a else config.VOIP_INTERVAL - time_in_cycle + offset_a
                    if wait_time > 0: yield self.env.timeout(wait_time)
                    self.stats["total_generated_data_pkts"] += 1
                    self.declare_tx_intent(self.env.now, granted_ch, src_ue.id)
                    success = self.transmit_message(
                        UAVRelayData, src_ue, self.uav, self.uav.id,
                        subchannel=granted_ch, sequence_number=seq_src,
                        destination_ip=target_ip, payload_data=secrets.token_hex(8), 
                        payload_type="VoIP (RTP)", generation_time=self.env.now
                    )
                    if not success: self.stats["voip_packets_dropped"] += 1
                    seq_src += 1
                    yield self.env.timeout(1)
                # Call Over - Free Grant
                yield dl_process
                if src_ue.status == UEState.CONNECTED and src_ue.sps_config is not None:
                    periodicity = src_ue.sps_config['periodicity']
                    offset = src_ue.sps_config['offset']
                    time_in_cycle = self.env.now % periodicity
                    wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
                    if wait_time > 0: yield self.env.timeout(wait_time)
                    if src_ue.status == UEState.CONNECTED:
                        self.declare_tx_intent(self.env.now, src_ue.sps_config['subchannel'], src_ue.id)
                        self.transmit_message(
                            ResourceRequest, src_ue, self.uav, self.uav.id,
                            subchannel=src_ue.sps_config['subchannel'],
                            bsr="0 Bytes", qos="Voice"
                        )
            else:
                self.stats["voip_packets_dropped"] += 1
                self.stats["total_generated_data_pkts"] += 1

        elif config.SIM_MODE == "BASELINE_U2N":
            # 1. SPUR THE EXTERNAL DOWNLINK PROCESS
            dl_process = self.env.process(self._external_voice_downlink_stream(src_ue, end_time))
            # 2. GUE Uplink Transmission Loop using Mode 2
            while self.env.now < end_time:
                if src_ue.status != UEState.CONNECTED: break
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission(
                    src_ue, self.uav, target_ip, seq_src, secrets.token_hex(8), payload_type="VoIP (RTP)"
                ))
                seq_src += 1
                yield self.env.timeout(config.VOIP_INTERVAL)
            yield dl_process # Make sure downlink finishes
        src_ue.app_state = "IDLE"

    def _external_voice_downlink_stream(self, dest_ue, end_time):
        """Simulates the Core Network pushing external voice frames down the Uu Backhaul."""
        seq_ext = random.randint(0, 1000)
        while self.env.now < end_time:
            if dest_ue.status != UEState.CONNECTED:
                break
            dest_ip = self.uav.connected_to.get(dest_ue.id, "::1")
            if config.SIM_MODE == "PROPOSED_U2N":
                self.stats["total_generated_data_pkts"] += 1
                # The packet has arrived at the UAV. It now drops into the UAV's data queue
                # so the UAV's MAC layer process will automatically forward it to the GUE.
                self.uav.data_tx_buffer.append({
                    "MsgClass": UAVRelayData,
                    "tx_node": self.uav,
                    "rx_node": dest_ue,
                    "dest_id": dest_ue.id,
                    "sequence_number": seq_ext,
                    "destination_ip": dest_ip, # Resolve to GUE IP
                    "payload_data": "EXTERNAL_RTP_PAYLOAD",
                    "payload_type": "VoIP (RTP) - External",
                    "generation_time": self.env.now
                })
                seq_ext += 1
                # Wait for the next 20ms voice frame cycle (minus the backhaul delay we already yielded)
                yield self.env.timeout(config.VOIP_INTERVAL)
            else:
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission( 
                    self.uav, 
                    dest_ue, 
                    dest_ip, 
                    seq_ext, 
                    secrets.token_hex(16), 
                    payload_type= "VoIP (RTP) - External", 
                    max_retries=0
                ))
                yield self.env.timeout(config.VOIP_INTERVAL)

    def _external_data_downlink_burst(self, dest_ue, num_packets):
        """Simulates the Core Network pushing an external data burst down the Uu Backhaul."""
        seq_ext = random.randint(0, 1000)
        # Simulate processing delay at the external server (e.g., web server generating response)
        yield self.env.timeout(random.randint(10, 50))
        for i in range(num_packets):
            if dest_ue.status != UEState.CONNECTED:
                break
            # Simulate the packet crossing the Uu interface
            dest_ip = self.uav.connected_to.get(dest_ue.id, "::1")
            if config.SIM_MODE == "PROPOSED_U2N":
                self.stats["total_generated_data_pkts"] += 1
                # The packet has arrived at the UAV. Drop it into the UAV's data queue.
                # The UAV's MAC layer process will automatically forward it to the GUE.
                self.uav.data_tx_buffer.append({
                    "MsgClass": UAVRelayData,
                    "tx_node": self.uav,
                    "rx_node": dest_ue,
                    "dest_id": dest_ue.id,
                    "sequence_number": seq_ext + i,
                    "destination_ip": dest_ip, # Resolve to GUE IP
                    "payload_data": secrets.token_hex(16),
                    "payload_type": "Data Burst - External DL",
                    "generation_time": self.env.now
                })
            else:
                # The UAV immediately tries to forward it using standard Mode 2 random access
                self.stats["total_generated_data_pkts"] += 1
                self.env.process(self.perform_mode_2_transmission(
                    self.uav, 
                    dest_ue, 
                    dest_ip, 
                    seq_ext + i, 
                    secrets.token_hex(16), 
                    payload_type="Data Burst - External DL", 
                    max_retries=config.MAX_RETRANSMISSIONS
                ))

    def establish_backhaul_connection(self):
        """Asynchronous execution of the 3GPP RRC Handshake on the Uu Interface."""
        yield self.env.timeout(100) # slight boot-up delay
        # 1. System Information Broadcast (gNB -> UAV)
        self.log_callback(SystemInformationBroadcast(self.env.now, self.gnb.id, config.TX, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(SystemInformationBroadcast(self.env.now, self.uav.id, self.gnb.id, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 2. RRC Setup Request (UAV -> gNB)
        self.log_callback(RRCSetupRequest(self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(RRCSetupRequest(self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_TX) # processing gap
        # 3. RRC Setup (gNB -> UAV)
        self.log_callback(RRCSetup(self.env.now, self.gnb.id, config.TX, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(RRCSetup(self.env.now, self.uav.id, self.gnb.id, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 4. RRC Setup Complete (UAV -> gNB)
        self.log_callback(RRCSetupComplete(self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(RRCSetupComplete(self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 5. Security Mode Command (gNB -> UAV)
        self.log_callback(SecurityModeCommand(self.env.now, self.gnb.id, config.TX, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(SecurityModeCommand(self.env.now, self.uav.id, self.gnb.id, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 6. Security Mode Complete (UAV -> gNB)
        self.log_callback(SecurityModeComplete(self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(SecurityModeComplete(self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 7. UL Information Transfer (PDU Session Establishment Request) (UAV -> gNB)
        self.log_callback(PDUSessionEstablishmentRequest(self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(PDUSessionEstablishmentRequest(self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 8. RRC Reconfiguration (PDU Session Accept & Prefix Delegation) (gNB -> UAV)
        self.log_callback(RRCReconfiguration(self.env.now, self.gnb.id, config.TX, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(RRCReconfiguration(self.env.now, self.uav.id, self.gnb.id, self.uav.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # 9. RRC Reconfiguration Complete (UAV -> gNB)
        self.log_callback(RRCReconfigurationComplete(self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        self.log_callback(RRCReconfigurationComplete(self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav))
        yield self.env.timeout(config.DELAY_TX)
        # Backhaul is now officially established
        self.gnb.status = "CONNECTED"
        # print(f"[{self.env.now}ms] Uu Backhaul Connection Established.")

    def report_remote_ue(self, remote_ue_id, allocated_ip="Unknown"):
        """
        Asynchronous execution of the NAS Remote UE Reporting over the Uu Interface.
        This informs the Core Network that a new D2D UE has joined the relay connection.
        """
        yield self.env.timeout(config.DELAY_TX) # Slight delay after PC5 connection completes
        # 1. UL Information Transfer (Remote UE Report) (UAV -> gNB)
        # The UAV encapsulates the NAS report in an RRC uplink message and transmits it
        self.log_callback(RemoteUEReport(
            self.env.now, self.uav.id, config.TX, self.gnb.id, self.uav, 
            remote_ue_id=remote_ue_id, allocated_ip=allocated_ip
        ))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        # gNB receives the uplink message
        self.log_callback(RemoteUEReport(
            self.env.now, self.gnb.id, self.uav.id, self.gnb.id, self.uav, 
            remote_ue_id=remote_ue_id, allocated_ip=allocated_ip
        ))
        yield self.env.timeout(config.DELAY_TX) # Core Network Processing Delay
        # 2. DL Information Transfer (Remote UE Report Ack) (gNB -> UAV)
        # The Core Network authorizes the UE and the gNB forwards the NAS Ack down to the UAV
        self.log_callback(RemoteUEReport_Ack(
            self.env.now, self.gnb.id, config.TX, self.uav.id, self.uav, 
            remote_ue_id=remote_ue_id
        ))
        yield self.env.timeout(config.DELAY_BACKHAUL)
        # UAV receives the downlink acknowledgment
        self.log_callback(RemoteUEReport_Ack(
            self.env.now, self.uav.id, self.gnb.id, self.uav.id, self.uav, 
            remote_ue_id=remote_ue_id
        ))
        yield self.env.timeout(config.DELAY_TX)

    def dump_collision_debug_state(self, collision_type, time, subchannel, tx_node, rx_node, msg_class):
        """Dumps the simulation state to a file when a post-setup collision occurs."""
        import datetime
        filename = "post_setup_collision_debug.txt"
        utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        def write_to_log():
            with open(filename, "a") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"COLLISION DETECTED: {collision_type}\n")
                f.write(f"Real Time: {utc_now}\n")
                f.write(f"Config: {config.NUM_GUES} UEs | Mode: {config.SIM_MODE}\n")
                f.write(f"Sim Time: {time} ms | Subchannel: {subchannel}\n")
                f.write(f"Transmitter: {tx_node.id} | Intended Receiver: {rx_node.id}\n")
                f.write(f"Message Class: {msg_class.__name__}\n\n")
                # 1. Investigate the Airwaves (tx_intent)
                key = (time, subchannel)
                transmitters = self.tx_intent.get(key, set())
                f.write(f"Nodes attempting TX on Ch {subchannel} at {time}ms: {list(transmitters)}\n")
                # If Half-Duplex, find out what the receiver was busy doing
                if collision_type == "HALF_DUPLEX":
                    rx_tx_channels = [ch for (t, ch), nodes in self.tx_intent.items() if t == time and rx_node.id in nodes]
                    f.write(f"Why HD? Receiver {rx_node.id} was busy transmitting on Channels: {rx_tx_channels}\n")
                f.write("\n--- COLLIDING NODE INTERNAL STATES ---\n")
                for node_id in transmitters:
                    node_obj = next((n for n in self.ues if n.id == node_id), None)
                    if node_obj:
                        f.write(f"[{node_id} State]\n")
                        f.write(f"  App State: {getattr(node_obj, 'app_state', 'N/A')}\n")
                        f.write(f"  Connection Status: {node_obj.status}\n")
                        f.write(f"  SPS Config: {node_obj.sps_config}\n")
                        f.write(f"  Active Grant: {node_obj.active_grant}\n")
                    elif node_id == self.uav.id:
                        f.write(f"[{node_id} State] -> UAV Downlink/Control Transmission\n")
                # 2. Dump the UAV Scheduler Dictionary States
                f.write("\n--- UAV SCHEDULER STATE ---\n")
                if hasattr(self, 'uav') and self.uav and hasattr(self.uav, 'scheduler'):
                    sched = self.uav.scheduler
                    f.write("[Control Plane SPS Grants (Ch 0 & 1)]\n")
                    for uid, grant in sched.active_sps_grants.items():
                        f.write(f"  {uid} -> Ch: {grant['subchannel']}, Offset: {grant['offset']}ms\n")
                    f.write("\n[User Plane PERIODIC Grants (Voice)]\n")
                    for (ch, offset), grant in sched.active_periodic_grants.items():
                        f.write(f"  Ch: {ch}, Relative Offset: {offset}ms -> UE: {grant['ue_id']}\n")
                    f.write("\n[User Plane APERIODIC Grants (Data Bursts)]\n")
                    for (ch, absolute_time), grant in sched.active_aperiodic_grants.items():
                        f.write(f"  Ch: {ch}, Absolute Time: {absolute_time}ms -> UE: {grant['ue_id']} (Expires at {grant['expires_at']}ms)\n")
                f.write(f"{'='*60}\n")
        if hasattr(self, 'file_lock') and self.file_lock is not None:
            with self.file_lock:
                write_to_log()
        else:
            write_to_log()

    def uav_flight_process(self):
        """Thesis Stage 7: Autonomous Positioning Algorithm and Flight Mechanics."""
        while True:
            yield self.env.timeout(config.POSITION_UPDATE_INTERVAL)
            if not self.uav.gue_telemetry:
                continue 
            sum_x = sum(data["x"] for data in self.uav.gue_telemetry.values())
            sum_y = sum(data["y"] for data in self.uav.gue_telemetry.values())
            target_x = sum_x / len(self.uav.gue_telemetry)
            target_y = sum_y / len(self.uav.gue_telemetry)
            self.uav.target_pos = (target_x, target_y)
            dx = target_x - self.uav.pos.x()
            dy = target_y - self.uav.pos.y()
            dist_to_target = math.hypot(dx, dy)
            if dist_to_target < 1.0:
                continue 
            seconds_passed = config.POSITION_UPDATE_INTERVAL / 1000.0
            max_travel_dist = config.UAV_SPEED_M_S * seconds_passed
            if dist_to_target <= max_travel_dist:
                self.uav.pos = QPointF(target_x, target_y)
            else:
                ratio = max_travel_dist / dist_to_target
                new_x = self.uav.pos.x() + (dx * ratio)
                new_y = self.uav.pos.y() + (dy * ratio)
                self.uav.pos = QPointF(new_x, new_y)
    
    def log_network_health(self):
        """Periodically records the ground truth SNR to prove mobility improves the link."""
        while True:
            yield self.env.timeout(1000)
            connected_ues = [ue for ue in self.ues if ue.status == UEState.CONNECTED]
            if len(connected_ues) > 0:
                snr_list = []
                for ue in connected_ues:
                    dist = self.calculate_3d_dist(self.uav, ue)
                    metrics = self.sdr.get_link_metrics(dist)
                    snr_list.append(metrics["snr_db"])
                avg_snr = sum(snr_list) / len(snr_list)
                min_snr = min(snr_list)
                curr_x = self.uav.pos.x()
                curr_y = self.uav.pos.y()
                target_x, target_y = getattr(self.uav, 'target_pos', (curr_x, curr_y))
                self.snr_history.append((self.env.now, avg_snr, min_snr, curr_x, curr_y, target_x, target_y))