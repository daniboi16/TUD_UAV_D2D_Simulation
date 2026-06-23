# simulation_engine.py
import simpy, math, config, random, copy, csv
from sdr import RadioChannel
from sim_traffic import TrafficMixin
from protocols import *

class ConnectionContext:
    """
    Holds the state and security parameters for ONE link between two nodes.
    """
    def __init__(self, remote_id, ip_address = None):
        self.remote_id = remote_id
        self.ipv6_address = ip_address 
             
class SimulationEngine(TrafficMixin):
    def __init__(self, file_lock=None):
        self.env = simpy.Environment()
        self.file_lock = file_lock
        self.setup_complete_time = None
        self.uav = None
        self.gnb = None
        self.ues = []
        self.log_callback = None
        self.resource_callback = None 
        self.spectrum_usage = set()
        self.tx_intent = {}
        self.sdr = RadioChannel()
        self.stats = {
            "total_transmissions": 0,
            "control_plane_tx": 0,
            "user_plane_tx": 0,
            "successful_decodes": 0,
            "collisions": 0,
            "half_duplex_collisions": 0,
            "hd_uav_deaf": 0,            # UAV missed a packet because it was transmitting
            "hd_gue_deaf": 0,            # GUE missed a packet because it was transmitting
            "snr_failures": 0,
            "retransmissions_attempted": 0,
            "packets_dropped_max_retries": 0,
            "data_packets_dropped": 0,  # Fails after 3 retries
            "voip_packets_dropped": 0,   # Fails instantly (0 retries)
            "e2e_delay_sum": 0,
            "e2e_delay_count": 0,
            "scheduling_delay_sum": 0,
            "scheduling_delay_count": 0,
            "implicit_link_failures": 0,
            "admission_rejections": 0,
            "connection_attempts": 0,
            "successful_data_bytes": 0,
            "total_generated_data_pkts": 0,
            "post_setup_physical_collisions": 0,
            "post_setup_hd_collisions": 0
        }
        self.snr_history = [] # Will hold tuples of (time_ms, avg_snr, min_snr)

    def run_step(self, until):
        """Executes all scheduled events up to the 'until' timestamp."""
        self.env.run(until=until)
    
    def start(self, uav, ues, gnb=None):
        self.uav = uav
        self.gnb = gnb
        self.ues = ues
        self.env.process(self.main_run_loop())
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"] and self.gnb:
            self.env.process(self.establish_backhaul_connection())
        if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"]:
            self.env.process(self.uav_mac_layer_process())
        if config.SIM_MODE == "POSITIONING_TEST":
            self.env.process(self.log_network_health())
            if config.UAV_MOBILITY:
                self.env.process(self.uav_flight_process())
        for ue in self.ues:
            if config.SIM_MODE in ["BASELINE_U2U", "PROPOSED_U2U"]:
                self.env.process(self.ue_traffic_generator(ue))
            elif config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"]:
                self.env.process(self.ue_u2n_traffic_generator(ue))
            if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"]:
                self.env.process(self.gue_telemetry_heartbeat(ue))

    def main_run_loop(self):
        """The Central Engine: Orchestrates node behaviors every step."""
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"] and self.gnb:
            while self.gnb.status != "CONNECTED":
                yield self.env.timeout(config.SIM_STEP)
        while True:
            if self.env.now % 200 == 0 and self.env.now > 0:
                self._prune_tx_intent(self.env.now - 200)
            # 1. UAV Logic: Broadcast Discovery every 1000ms
            if self.env.now % 1000 == 0:
                self.handle_uav_discovery()
            # 2. Check for implicit release
            if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"] and self.env.now % config.SUPER_FRAME_MS == 0:
                self.check_implicit_releases()
            # 2. UE Logic: Each UE evaluates its environment
            for ue in self.ues:
                self.handle_ue_logic(ue)
            yield self.env.timeout(config.SIM_STEP)

    def gue_telemetry_heartbeat(self, ue):
        """
        Thesis Stage 7: The Unified Telemetry Heartbeat.
        Runs continuously once a GUE is connected in PROPOSED_U2U mode.
        """
        while True:
            if ue.status != UEState.CONNECTED or ue.sps_config is None:
                yield self.env.timeout(config.SIM_STEP)
                continue
            current_time = self.env.now
            periodicity = ue.sps_config['periodicity']
            offset = ue.sps_config['offset']
            time_in_cycle = current_time % periodicity
            if time_in_cycle <= offset:
                wait_time = offset - time_in_cycle
            else:
                wait_time = periodicity - time_in_cycle + offset
            if wait_time > 0:
                yield self.env.timeout(wait_time)
            if ue.status != UEState.CONNECTED or ue.sps_config is None:
                continue
            yield self.env.timeout(0) 
            if self.is_node_transmitting(self.env.now, ue.id):
                yield self.env.timeout(1)
                continue
            dist = self.calculate_3d_dist(ue, self.uav)
            metrics = self.sdr.get_link_metrics(dist)
            self.declare_tx_intent(self.env.now, ue.sps_config['subchannel'], ue.id)
            self.transmit_message(
                StatusReport, 
                ue, 
                self.uav, 
                self.uav.id, 
                subchannel=ue.sps_config['subchannel'],
                lat=f"{ue.pos.x():.1f}",
                lon=f"{ue.pos.y():.1f}",
                s_rsrp=f"{metrics['rsrp_dbm']:.1f} dBm"
            )
            yield self.env.timeout(1)

    def handle_resource_request(self, request_msg):
        """UAV processes a Resource Request and issues a Resource Grant strictly in the DL phase."""
        target_node = next((ue for ue in self.ues if ue.id == request_msg.source_id), None)
        if target_node: 
            app_layer = request_msg.stack.get("Application", {})
            bsr = app_layer.get("Buffer-Status-Report (BSR)", "")
            qos_class = app_layer.get("QoS-Class", "Best Effort")
            if bsr == "0 Bytes":
                self.uav.scheduler.release_data_channel(target_node.id)
                target_node.active_grant = None
                return
            is_periodic = (qos_class == "Voice")
            if is_periodic:
                num_packets = 1
            else:
                try:
                    bytes_requested = int(bsr.split(" ")[0])
                    num_packets = math.ceil(bytes_requested / config.PACKET_SIZE_BYTES)
                except (ValueError, AttributeError):
                    num_packets = 1
            grants = self.uav.scheduler.allocate_data_channel(
                request_msg.source_id, 
                self.env.now, 
                is_periodic, 
                num_packets
            )
            if len(grants) > 0:
                target_node.active_grant = grants
                uav_rx_time = self.env.now + config.DELAY_TX
                slot_in_frame = uav_rx_time % config.TDD_FRAME_MS
                if 0 < slot_in_frame < config.TDD_DL_MS:
                    queuing_delay = 1
                else:
                    queuing_delay = (config.TDD_FRAME_MS - slot_in_frame) + 1
                total_delay = config.DELAY_TX + queuing_delay + config.DELAY_TX
                target_node.grant_rx_time = self.env.now + total_delay
                self.uav.tx_buffer.append({
                    "MsgClass": ResourceGrant,
                    "tx_node": self.uav,
                    "rx_node": target_node,
                    "dest_id": target_node.id,
                    "subchannel": config.CONTROL_CH_UAV,
                    "resource_index": f"Assigned {len(grants)} Slots"
                })

    def perform_dns_resolution(self, ue, relay, target_ue):
        """
        Simulates the DNS Query/Response exchange defined in TS 23.304.
        """
        fqdn = f"{target_ue.id}.prose"
        if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"] or ue.sps_config is not None:
            periodicity = ue.sps_config['periodicity']
            offset = ue.sps_config['offset']
            ul_channel = ue.sps_config['subchannel']
            time_in_cycle = self.env.now % periodicity
            wait_time = offset - time_in_cycle if time_in_cycle <= offset else periodicity - time_in_cycle + offset
            yield self.env.timeout(wait_time)
            yield self.env.timeout(0) 
            while self.is_node_transmitting(self.env.now, ue.id):
                yield self.env.timeout(periodicity)
                yield self.env.timeout(0)
        else:
            yield self.env.timeout(config.DNS_SELECTION_WINDOW)
            ul_channel = random.randint(0, config.NUM_SUBCHANNELS - 1)
        self.declare_tx_intent(self.env.now, ul_channel, ue.id)
        self.transmit_message(
            DNSQuery, 
            ue, 
            relay, 
            relay.id, 
            subchannel=ul_channel, 
            query_name=fqdn, 
            transaction_id=random.randint(0, 65535)
        )
        yield self.env.timeout(config.DNS_LOOKUP_DELAY)
        resolved_ip = relay.connected_to.get(target_ue.id, "::1")
        if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"]:
            self.uav.tx_buffer.append({
                "MsgClass": DNSResponse,
                "tx_node": relay,
                "rx_node": ue,
                "dest_id": ue.id,
                "subchannel": config.CONTROL_CH_UAV,
                "query_name": fqdn,
                "resolved_ip": resolved_ip,
                "transaction_id": random.randint(0, 65535)
            })
            ue.dns_cache[target_ue.id] = resolved_ip
        else:
            yield self.env.timeout(config.DELAY_TX)
            dl_channel = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, dl_channel, relay.id)
            success = self.transmit_message(
                DNSResponse,
                relay,
                ue,
                ue.id,
                subchannel=dl_channel,
                query_name=fqdn,
                resolved_ip=resolved_ip,
                transaction_id=random.randint(0, 65535)
            )
            if success:
                ue.dns_cache[target_ue.id] = resolved_ip # Update the User's Cache

    def perform_mode_2_transmission(self, source_node, relay_node, target_ip, seq_num, random_payload, payload_type, max_retries=0):
        """
        Simulates 3GPP Mode 2 (Infrastructure-less) Resource Allocation.
        Current Baseline: Random Selection within Window.
        """
        true_gen_time = self.env.now
        t1 = 1 
        t2 = config.SELECTION_WINDOW_MAX
        time_offset = random.randint(t1, t2)
        yield self.env.timeout(time_offset)
        for attempt in range(max_retries + 1):
            if attempt > 0:
                self.stats["retransmissions_attempted"] += 1
            chosen_subchannel = random.randint(0, config.NUM_SUBCHANNELS - 1)
            display_payload = payload_type
            if attempt > 0:
                display_payload = f"{payload_type} (Retry {attempt})"
            self.declare_tx_intent(self.env.now, chosen_subchannel, source_node.id)
            success = self.transmit_message(
                UAVRelayData, 
                source_node, 
                relay_node,    
                relay_node.id,
                subchannel=chosen_subchannel,
                sequence_number=seq_num,
                destination_ip=target_ip,
                payload_data=random_payload,
                payload_type=display_payload,
                generation_time=true_gen_time
            )
            if success:
                break 
            elif attempt < max_retries:
                yield self.env.timeout(config.RETRANSMISSION_BACKOFF)
            else:
                if max_retries > 0:
                    self.stats["data_packets_dropped"] += 1
                else:
                    self.stats["voip_packets_dropped"] += 1
    
    def register_and_check_collision(self, time_slot, subchannel, tx_node_id):
        """
        Registers a transmission in the physical airwaves.
        Returns True if a collision occurs (multiple nodes on same time/freq).
        """
        key = (time_slot, subchannel)
        self.spectrum_usage.add(key)
        is_collision = len(self.tx_intent.get(key, [])) > 1
        if self.resource_callback:
            self.resource_callback(time_slot, subchannel, tx_node_id, is_collision)
        return is_collision
    
    def is_node_transmitting(self, time_slot, node_id):
        """Checks if a node is actively transmitting on ANY subchannel during this time slot."""
        for (t, ch), nodes in self.tx_intent.items():
            if t == time_slot and node_id in nodes:
                return True
        return False
    
    def are_all_ues_connected(self):
        """Returns True only if 100% of the UEs in the simulation are currently connected."""
        if len(self.ues) == 0:
            return False
        is_all_connected = all(ue.status == UEState.CONNECTED for ue in self.ues)
        if is_all_connected:
            if self.setup_complete_time is None:
                self.setup_complete_time = self.env.now
        else:
            self.setup_complete_time = None 
        return is_all_connected

    def handle_uav_discovery(self):
        """UAV sends out the heartbeat."""
        if "U2N" in config.SIM_MODE:
            tx_msg = DiscoverAnnouncment_UE_Network_Relay(self.env.now, self.uav.id, config.TX, "0xFFFF",  self.uav)
        else:
            tx_msg = DiscoverAnnouncment_UE_UE_Relay(self.env.now, self.uav.id, config.TX, "0xFFFF",  self.uav)
        self.log_callback(tx_msg)
        for ue in self.ues:
            dist = self.calculate_3d_dist(self.uav, ue)
            metrics = self.sdr.get_link_metrics(dist)
            is_decoded = self.sdr.attempt_reception(metrics["snr_db"])
            if is_decoded:
                if "U2N" in config.SIM_MODE:
                    rx_msg = DiscoverAnnouncment_UE_Network_Relay(self.env.now + config.DELAY_TX, ue.id, self.uav.id, ue.id, self.uav)
                else:
                    rx_msg = DiscoverAnnouncment_UE_UE_Relay(self.env.now + config.DELAY_TX, ue.id, self.uav.id, ue.id, self.uav)
                rx_msg.stack["RX"]["RSRP"] = f"{metrics['rsrp_dbm']:.1f} dBm"
                rx_msg.stack["RX"]["SNR"] = f"{metrics['snr_db']:.1f} dB"
                rx_msg.stack["RX"]["Distance"] = f"{dist:.1f} m"
                self.log_callback(rx_msg)
                ue.last_discovery_time = self.env.now

    def handle_ue_logic(self, ue):
        """Monitors the state machine for each UE."""
        dist = self.calculate_3d_dist(ue, self.uav)
        metrics = self.sdr.get_link_metrics(dist)
        is_link_good = self.sdr.attempt_reception(metrics["snr_db"])
        if ue.status == UEState.IDLE and is_link_good:
            if self.env.now == ue.last_discovery_time:
                ue.status = UEState.DISCOVERING
                self.stats["connection_attempts"] += 1 
                self.env.process(self.handshake_protocol_stack(ue))
        elif ue.status == UEState.CONNECTED:
            if metrics["snr_db"] < self.sdr.snr_threshold_disconected:
                ue.status = UEState.IDLE
                ue.connected_to = None
                self.remove_ue_connection(ue.id)

    def transmit_message(self, MsgClass, tx_node, rx_node, dest_id, subchannel=None, **kwargs):
        """
        Handles the dual-logging of a message: 
        1. Logs the 'Transmitted' event from the sender.
        2. Calculates link metrics and logs the 'Received' event if decoded.

        :param MsgClass: The class of the message (e.g., DirectCommunicationRequest)
        :param tx_node: The Sender Node Object (UAV or UE)
        :param rx_node: The Receiver Node Object
        :param dest_id_str: The L2 Destination ID string (e.g., "UAV_0" or "0xFF..")
        :param **kwargs: Any extra arguments your Message class needs (e.g., seq_num, payload)
        """
        if subchannel is None:
            subchannel = random.randint(0, config.NUM_SUBCHANNELS - 1)
        is_collision = self.register_and_check_collision(self.env.now, subchannel, tx_node.id)
        # 1. Log the Transmission from the source node's perspective
        try:
            tx_msg = MsgClass(self.env.now, tx_node.id, config.TX, dest_id, self.uav, **kwargs)
        except TypeError:
            tx_msg = MsgClass(self.env.now, tx_node.id, config.TX, dest_id, self.uav)
        self.log_callback(tx_msg)
        self.stats["total_transmissions"] += 1
        if tx_msg.plane == "Control":
            self.stats["control_plane_tx"] += 1
        else:
            self.stats["user_plane_tx"] += 1
        if is_collision:
            self.stats["collisions"] += 1 
            if self.are_all_ues_connected() and self.env.now > self.setup_complete_time:
                self.stats["post_setup_physical_collisions"] += 1
                if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"]:
                    self.dump_collision_debug_state(
                        "PHYSICAL", self.env.now, subchannel, tx_node, rx_node, MsgClass
                    )
            return False
        if self.is_node_transmitting(self.env.now, rx_node.id):
            self.stats["half_duplex_collisions"] += 1 
            if self.are_all_ues_connected() and self.env.now > self.setup_complete_time:
                self.stats["post_setup_hd_collisions"] += 1
                if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N"]:
                    self.dump_collision_debug_state(
                        "HALF_DUPLEX", self.env.now, subchannel, tx_node, rx_node, MsgClass
                    )
            if rx_node.id == self.uav.id:
                self.stats["hd_uav_deaf"] += 1
            else:
                self.stats["hd_gue_deaf"] += 1
            if hasattr(self, 'hd_callback') and self.hd_callback:
                self.hd_callback(self.env.now, subchannel, "HD_COLLISION")
            return False 
        # 2. Calculate Link Metrics for the receiver
        dist = self.calculate_3d_dist(tx_node, rx_node)
        metrics = self.sdr.get_link_metrics(dist)
        is_decoded = self.sdr.attempt_reception(metrics["snr_db"])
        # 3. If the link is good, log the Reception at the destination
        if is_decoded:
            self.stats["successful_decodes"] += 1
            rx_msg = copy.deepcopy(tx_msg)
            rx_msg.time = self.env.now + config.DELAY_TX        # Add propagation delay
            rx_msg.node_id = rx_node.id                         # The Logger is now the Receiver
            rx_msg.source_id = tx_node.id                       # The Source is the Sender (not "Transmitted")
            if isinstance(rx_msg, UAVRelayData) and rx_node.node_type == "Ground UE":
                gen_time = rx_msg.stack["Application"].get("Generation-Time", self.env.now)
                payload_type = rx_msg.stack["Application"].get("Payload-Type", "")
                if "External" in payload_type:
                    physical_delay = config.DELAY_BACKHAUL + config.DELAY_TX # U2N Downlink: gNB -> UAV (Backhaul) + UAV -> GUE (PC5)
                else:
                    physical_delay = config.DELAY_TX * 2 # U2U: GUE A -> UAV (PC5) + UAV -> GUE B (PC5)
                self.stats["e2e_delay_sum"] += ((self.env.now + physical_delay) - gen_time)
                self.stats["e2e_delay_count"] += 1
                self.stats["successful_data_bytes"] += config.PACKET_SIZE_BYTES
            rx_msg.stack["RX"]["RSRP"] = f"{metrics['rsrp_dbm']:.1f} dBm"
            rx_msg.stack["RX"]["SNR"] = f"{metrics['snr_db']:.1f} dB"
            rx_msg.stack["RX"]["Distance"] = f"{dist:.1f} m"
            self.log_callback(rx_msg)
            if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"] and rx_node.id == self.uav.id:
                if isinstance(rx_msg, (StatusReport, ResourceRequest, UAVRelayData, DNSQuery)):
                    self.uav.last_heartbeat_rx[tx_node.id] = self.env.now 
                    if config.SIM_MODE == "POSITIONING_TEST" and isinstance(rx_msg, StatusReport):
                        try:
                            lat_str = rx_msg.stack["Application"].get("Latitude", "0")
                            lon_str = rx_msg.stack["Application"].get("Longitude", "0")
                            rsrp_str = rx_msg.stack["Application"].get("S-RSRP", "-100 dBm")
                            self.uav.gue_telemetry[tx_node.id] = {
                                "x": float(lat_str),
                                "y": float(lon_str),
                                "rsrp": float(rsrp_str.split(" ")[0])
                            }
                        except ValueError:
                            pass
                    if isinstance(rx_msg, ResourceRequest):
                        self.handle_resource_request(rx_msg)
                    if isinstance(rx_msg, UAVRelayData):
                        dest_ip = rx_msg.stack["Application"]["Destination-IP"]
                        seq_num = rx_msg.stack["Application"]["Data-Seq-Num"]
                        payload_type = rx_msg.stack["Application"]["Payload-Type"]
                        preserved_payload = rx_msg.stack["DATA"]["Data"]
                        gen_time = rx_msg.stack["Application"].get("Generation-Time", self.env.now)
                        target_ue_id = None
                        for ue_id, ip in self.uav.connected_to.items():
                            if ip == dest_ip:
                                target_ue_id = ue_id
                                break
                        if target_ue_id:
                            dest_node = next((ue for ue in self.ues if ue.id == target_ue_id), None)
                            if dest_node:
                                self.uav.data_tx_buffer.append({
                                    "MsgClass": UAVRelayData,
                                    "tx_node": self.uav,
                                    "rx_node": dest_node,
                                    "dest_id": dest_node.id,
                                    "sequence_number": seq_num,
                                    "destination_ip": dest_ip,
                                    "payload_data": preserved_payload,
                                    "payload_type": payload_type,
                                    "generation_time": gen_time
                                })
                        elif dest_ip == config.EXTERNAL_SERVER_IP and self.gnb and self.gnb.status == "CONNECTED":
                            self.stats["e2e_delay_sum"] += ((self.env.now + config.DELAY_TX + config.DELAY_BACKHAUL) - gen_time)
                            self.stats["e2e_delay_count"] += 1
                            self.stats["successful_data_bytes"] += config.PACKET_SIZE_BYTES
                            self.log_callback(UAVRelayData(
                                sim_time=self.env.now,
                                node_id=self.uav.id,
                                source_id=config.TX,
                                destination_id=self.gnb.id,
                                uav=self.uav,
                                sequence_number=seq_num,
                                destination_ip=dest_ip,
                                payload_data=preserved_payload,
                                payload_type=payload_type,
                                generation_time=gen_time
                            ))
            if config.SIM_MODE in ["BASELINE_U2U", "BASELINE_U2N"]:
                if rx_node == self.uav and isinstance(rx_msg, UAVRelayData):
                    self.env.process(self.handle_packet_relaying(rx_msg))
            return True
        else:
            self.stats["snr_failures"] += 1
        return False
    
    def handle_packet_relaying(self, received_msg):
        """
        Simulates the L3 Relay Routing function (TS 23.304).
        1. Reads Destination IP from the received packet.
        2. Looks up the Target UE's L2 ID (ARP Table / Internal Map).
        3. Forwards the packet on the egress link.
        """
        # 1. Simulate Processing Delay (Routing lookup + Queuing)
        processing_delay = random.randint(5, 15) 
        downlink_channel = random.randint(0, config.NUM_SUBCHANNELS - 1)
        yield self.env.timeout(processing_delay)
        # 2. Extract Packet Info
        dest_ip = received_msg.stack["Application"]["Destination-IP"]
        gen_time = received_msg.stack["Application"].get("Generation-Time", self.env.now)
        seq_num = received_msg.stack["Application"]["Data-Seq-Num"]
        payload_type = received_msg.stack["Application"]["Payload-Type"]
        preserved_payload = received_msg.stack["DATA"]["Data"]
        # 3. Routing Table Lookup (Reverse Lookup: IP -> Node object)
        target_ue_id = None
        for ue_id, ip in self.uav.connected_to.items():
            if ip == dest_ip:
                target_ue_id = ue_id
                break
        if target_ue_id:
            target_node = next((ue for ue in self.ues if ue.id == target_ue_id), None)
            if target_node:
                # 4. Forward the Packet (Downlink: UAV -> Target UE)
                self.declare_tx_intent(self.env.now, downlink_channel, self.uav.id)
                success = self.transmit_message(
                    UAVRelayData,
                    self.uav,      # Source Node
                    target_node,   # Receiver Node
                    target_node.id,# L2 Dest ID
                    subchannel=downlink_channel,
                    sequence_number=seq_num,
                    destination_ip=dest_ip, 
                    payload_data=preserved_payload,
                    generation_time=gen_time
                )
                if not success:
                    if payload_type == "VoIP (RTP)":
                        self.stats["voip_packets_dropped"] += 1
                    else:
                        self.stats["data_packets_dropped"] += 1
            elif dest_ip == config.EXTERNAL_SERVER_IP and self.gnb and self.gnb.status == "CONNECTED":
                self.stats["e2e_delay_sum"] += ((self.env.now + config.DELAY_TX + config.DELAY_BACKHAUL) - gen_time)
                self.stats["e2e_delay_count"] += 1
                self.stats["successful_data_bytes"] += config.PACKET_SIZE_BYTES
                self.log_callback(UAVRelayData(
                    sim_time=self.env.now, 
                    node_id=self.uav.id, 
                    source_id=config.TX, 
                    destination_id=self.gnb.id, 
                    uav=self.uav,
                    sequence_number=seq_num,
                    destination_ip=dest_ip,
                    payload_data=preserved_payload,
                    payload_type=payload_type,
                    generation_time=gen_time
                ))

    def handshake_protocol_stack(self, ue):
        """Asynchronous execution of the 5-step 3GPP handshake."""
        if ue.status == UEState.DISCOVERING:
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX))
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, ue.id)
            success = self.transmit_message(DirectCommunicationRequest, ue, self.uav, self.uav.id, subchannel=ch)
            if success:
                ue.status = UEState.DISCOVERED
            else:
                ue.status = UEState.IDLE
        if ue.status == UEState.DISCOVERED:
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX))
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, self.uav.id)
            success = self.transmit_message(DirectSecurityModeCommand, self.uav, ue, ue.id, subchannel=ch)
            if success:
                ue.status = UEState.AUTHENTICATING
            else:
                ue.status = UEState.IDLE
        if ue.status == UEState.AUTHENTICATING:
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX))
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, ue.id)
            success = self.transmit_message(DirectSecurityModeComplete, ue, self.uav, self.uav.id, subchannel=ch)
            if success:
                ue.status = UEState.AUTHENTICATED
            else:
                ue.status = UEState.IDLE
        if ue.status == UEState.AUTHENTICATED:
            # --- STEP 5: DIRECT_COMMUNICATION_ACCEPT (Relay -> UE) ---
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX)) 
            sps_kwargs = {}
            if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"]:
                ue.sps_config = self.uav.scheduler.allocate_sps_slot(ue.id)
                if ue.sps_config is None:
                    self.stats["admission_rejections"] += 1
                    ue.status = UEState.IDLE
                    return
                sps_kwargs = {"sps_allocation": f"Ch:{ue.sps_config['subchannel']}, Offset:{ue.sps_config['offset']}ms"}
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, self.uav.id)
            success = self.transmit_message(DirectCommunicationAccept, self.uav, ue, ue.id, subchannel=ch, **sps_kwargs)
            if success:
                ue.status = UEState.CONNECTED_L2
                ue.connected_to = {self.uav.id: self.uav.local_ip_address}
                self.uav.status = UAVState.CONNECTED
                self.uav.connected_to[ue.id] = None
            else:
                ue.status = UEState.IDLE
        if ue.status == UEState.CONNECTED_L2: 
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX))
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, ue.id)
            success = self.transmit_message(RouterSolicitation, ue, self.uav, self.uav.id, subchannel=ch)
            if success:
                ue.status = UEState.CONNECTING_L3
                assigned_ip_addr = config.UNUSED_IP_ADDR[0]
                config.IN_USE_IP_ADDR.append(assigned_ip_addr)
                config.UNUSED_IP_ADDR.remove(assigned_ip_addr)
                self.uav.connected_to[ue.id] = assigned_ip_addr
            else:
                ue.status = UEState.IDLE
        if ue.status == UEState.CONNECTING_L3: 
            yield self.env.timeout(random.randint(config.DELAY_MIN, config.DELAY_MAX))
            ch = random.randint(0, config.NUM_SUBCHANNELS - 1)
            self.declare_tx_intent(self.env.now, ch, self.uav.id)
            success = self.transmit_message(RouterAdvertisement, self.uav, ue, ue.id, subchannel=ch)
            if success:
                ue.status = UEState.CONNECTED
                if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"] and self.gnb:
                    assigned_ip = self.uav.connected_to[ue.id]
                    self.env.process(self.report_remote_ue(remote_ue_id=ue.id, allocated_ip=str(assigned_ip))) 
                if config.SIM_MODE in ["PROPOSED_U2U", "PROPOSED_U2N", "POSITIONING_TEST"]:
                    self.uav.last_heartbeat_rx[ue.id] = self.env.now
            else:
                ue.status = UEState.IDLE

    def check_implicit_releases(self):
        """Thesis Stage 8: Implicit Connection Release."""
        timeout_threshold = config.SUPER_FRAME_MS * config.NO_OF_HEARTBEAT_MISSED 
        dead_nodes = []
        for ue_id, last_seen in self.uav.last_heartbeat_rx.items():
            if self.env.now - last_seen > timeout_threshold:
                dead_nodes.append(ue_id)
        for ue_id in dead_nodes:
            self.remove_ue_connection(ue_id)
            self.stats["implicit_link_failures"] += 1
            del self.uav.last_heartbeat_rx[ue_id]
            for ue in self.ues:
                if ue.id == ue_id:
                    ue.status = UEState.IDLE
                    ue.sps_config = None
                    ue.dns_cache = {}
                    # print(f"[{self.env.now} ms] UAV implicitly released {ue_id} due to missed heartbeats.")

    def declare_tx_intent(self, target_time, subchannel, node_id):
        """Registers that a node WILL transmit at a specific future millisecond."""
        key = (target_time, subchannel)
        if key not in self.tx_intent:
            self.tx_intent[key] = set()
        self.tx_intent[key].add(node_id)

    def _prune_tx_intent(self, before_time):
        """Removes stale transmission intents to prevent memory leaks."""
        keys_to_delete = [k for k in self.tx_intent if k[0] < before_time]
        for k in keys_to_delete:
            del self.tx_intent[k]

    def remove_ue_connection(self, remove_ue_id):
        """Centralized cleanup when a UE drops or fails to connect."""
        ip_addr = self.uav.connected_to.get(remove_ue_id)
        if ip_addr is not None:
            if ip_addr in config.IN_USE_IP_ADDR:
                config.IN_USE_IP_ADDR.remove(ip_addr)
            config.UNUSED_IP_ADDR.append(ip_addr)
        if remove_ue_id in self.uav.connected_to:
            del self.uav.connected_to[remove_ue_id]
        self.uav.scheduler.release_sps_slot(remove_ue_id)
        self.uav.scheduler.release_data_channel(remove_ue_id)
        for ue in self.ues:
            if ue.id == remove_ue_id:
                ue.sps_config = None
                ue.active_grant = None
                ue.dns_cache = {}
                ue.status = UEState.IDLE

    def calculate_3d_dist(self, node_a, node_b):
        return math.sqrt(
            (node_a.pos.x() - node_b.pos.x())**2 +
            (node_a.pos.y() - node_b.pos.y())**2 +
            (node_a.alt - node_b.alt)**2
        )

    def export_stats_to_csv(self, filename="simulation_results.csv"):
        """Dumps the simulation metrics to a CSV file."""
        avg_e2e = self.stats.get("e2e_delay_sum", 0) / max(1, self.stats.get("e2e_delay_count", 0))
        avg_sched = self.stats.get("scheduling_delay_sum", 0) / max(1, self.stats.get("scheduling_delay_count", 0))
        pdr = 0
        if self.stats.get("total_generated_data_pkts", 0) > 0:
            pdr = (self.stats.get("e2e_delay_count", 0) / self.stats["total_generated_data_pkts"]) * 100
        implicit_fail_rate = 0
        admin_reject_rate = 0
        if self.stats.get("connection_attempts", 0) > 0:
            implicit_fail_rate = (self.stats.get("implicit_link_failures", 0) / self.stats["connection_attempts"]) * 100
            admin_reject_rate = (self.stats.get("admission_rejections", 0) / self.stats["connection_attempts"]) * 100
        total_blocks = max(1, self.env.now) * config.NUM_SUBCHANNELS
        spectrum_util = (len(self.spectrum_usage) / total_blocks) * 100
        throughput_kbps = 0
        if self.env.now > 0:
            throughput_kbps = (self.stats.get("successful_data_bytes", 0) * 8) / self.env.now # ms to sec cancels out with byte to kb

        total_tx = max(1, self.stats["total_transmissions"])
        reg_coll_pct = (self.stats["collisions"] / total_tx) * 100
        hd_coll_pct = (self.stats["half_duplex_collisions"] / total_tx) * 100
        total_coll_pct = reg_coll_pct + hd_coll_pct
        hd_uav_pct = (self.stats["hd_uav_deaf"] / total_tx) * 100
        hd_gue_pct = (self.stats["hd_gue_deaf"] / total_tx) * 100
        data = [
            ["Metric", "Value"],
            # --- Run Configuration ---
            ["Simulation Mode", config.SIM_MODE],
            ["Number of UEs", config.NUM_GUES],
            ["Run ID", "GUI Run"],        
            ["Random Seed", "N/A"],       
            # --- Base Transmission Counts ---
            ["Total Transmissions", self.stats["total_transmissions"]],
            ["Control Plane Transmissions", self.stats.get("control_plane_tx", 0)],
            ["User Plane Transmissions", self.stats.get("user_plane_tx", 0)],
            ["Total Generated Data Packets", self.stats.get("total_generated_data_pkts", 0)],
            ["Successful Decodes", self.stats["successful_decodes"]],
            ["Signal to Noise Ratio Failures", self.stats["snr_failures"]],
            ["Retransmissions Attempted", self.stats.get("retransmissions_attempted", 0)],
            ["Data Packets Dropped", self.stats["data_packets_dropped"]],
            ["Voice over IP Packets Dropped", self.stats["voip_packets_dropped"]],
            # --- Collision Counts ---
            ["Total Physical Collisions", self.stats["collisions"]],
            ["Total Half-Duplex Collisions", self.stats["half_duplex_collisions"]],
            ["Half-Duplex Collisions (UAV Deaf)", self.stats["hd_uav_deaf"]],
            ["Half-Duplex Collisions (Ground UE Deaf)", self.stats["hd_gue_deaf"]],
            ["Post-Setup Physical Collisions", self.stats.get("post_setup_physical_collisions", 0)],
            ["Post-Setup Half-Duplex Collisions", self.stats.get("post_setup_hd_collisions", 0)],
            # --- Percentages ---
            ["Physical Collision Rate (%)", f"{reg_coll_pct:.2f}"],
            ["Half-Duplex Collision Rate (%)", f"{hd_coll_pct:.2f}"],
            ["Total Collision Rate (%)", f"{total_coll_pct:.2f}"],
            ["Half-Duplex UAV Deafness Rate (%)", f"{hd_uav_pct:.2f}"],
            ["Half-Duplex Ground UE Deafness Rate (%)", f"{hd_gue_pct:.2f}"],
            # --- Latencies ---
            ["Average End-to-End Delay (ms)", f"{avg_e2e:.2f}"],
            ["Average Scheduling Delay (ms)", f"{avg_sched:.2f}"],
            # --- System Performance ---
            ["Packet Delivery Ratio (%)", f"{pdr:.2f}"],
            ["Aggregate Throughput (kbps)", f"{throughput_kbps:.2f}"],
            ["Spectrum Utilization (%)", f"{spectrum_util:.2f}"],
            ["Implicit Link Failure Rate (%)", f"{implicit_fail_rate:.2f}"],
            ["Admission Rejection Rate (%)", f"{admin_reject_rate:.2f}"]
        ]
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)
        print(f"Results successfully saved to {filename}")

    def export_time_series_to_csv(self):
        """Dumps the SNR history to a CSV for thesis plotting."""      
        if config.UAV_MOBILITY:
            filename = "mobile_uav_snr_results.csv"
        else:
            filename = "static_uav_snr_results.csv"    
        data = [["Time (ms)", "Average SNR (dB)", "Minimum SNR (dB)", "UAV Current X", "UAV Current Y", "Optimal Target X", "Optimal Target Y"]]
        for record in self.snr_history:
            data.append([
                record[0], 
                f"{record[1]:.2f}", 
                f"{record[2]:.2f}",
                f"{record[3]:.1f}",  # Current X
                f"{record[4]:.1f}",  # Current Y
                f"{record[5]:.1f}",  # Target X
                f"{record[6]:.1f}"   # Target Y
            ])
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)
        print(f"Time-series data successfully saved to {filename}")