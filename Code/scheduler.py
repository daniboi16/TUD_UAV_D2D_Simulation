#scheduler.py
import config

class UAVScheduler:
    """
    Centralised Resource Manager for the UAV-Governed PC5 architecture.
    Handles the assignment of orthogonal SPS slots to prevent collisions.
    """
    def __init__(self, num_subchannels):
        self.num_subchannels = num_subchannels
        self.sps_periodicity =  config.SUPER_FRAME_MS
        self.active_sps_grants = {}
        self.ch0_usage = set()
        self.active_periodic_grants = {}
        self.active_aperiodic_grants = {}  
        self.data_offset_counter = config.TDD_DL_MS 
        self.dl_usage = {} 
        self.valid_sps_offsets = [
            (frame_start + slot)
            for frame_start in range(0, config.SUPER_FRAME_MS, config.TDD_FRAME_MS)
            for slot in range(config.TDD_DL_MS, config.TDD_FRAME_MS)
        ]

    def allocate_sps_slot(self, ue_id):
        """Dynamically finds an unused control slot within the Uplink phase."""
        # 1. Look up which slots are currently taken on each channel
        used_ch1 = {g['offset'] for g in self.active_sps_grants.values() if g['subchannel'] == config.CONTROL_CH_GUE}
        used_ch0 = {g['offset'] for g in self.active_sps_grants.values() if g['subchannel'] == config.CONTROL_CH_UAV}
        assigned_offset = None
        assigned_channel = None
        # 2. Try to allocate on Channel 1 first (Capacity: 50)
        for offset in self.valid_sps_offsets:
            if offset not in used_ch1:
                assigned_offset = offset
                assigned_channel = config.CONTROL_CH_GUE
                break
        # 3. If Channel 1 is full, spill over to Channel 0 (Capacity: +50)
        if assigned_offset is None:
            for offset in self.valid_sps_offsets:
                if offset not in used_ch0:
                    assigned_offset = offset
                    assigned_channel = config.CONTROL_CH_UAV
                    break
        # 4. Handle Absolute Congestion (100+ users)
        if assigned_offset is None:
            # print(f"[{ue_id}] Admission Control: Network full, rejecting connection.")
            return None
        allocation = {
            "offset": assigned_offset,
            "subchannel": assigned_channel,
            "periodicity": self.sps_periodicity
        }
        self.active_sps_grants[ue_id] = allocation 
        return allocation

    def release_sps_slot(self, ue_id):
        """
        Explicitly frees a control plane SPS slot when a UE disconnects or dies.
        This allows the slot to be reassigned to a new UE entering the network.
        """
        if ue_id in self.active_sps_grants:
            self.active_sps_grants.pop(ue_id)

    def is_slot_free(self, ch, offset, current_time):
        """Helper function to ensure a slot is totally empty across BOTH dictionaries."""
        # 1. Check if a Voice call owns this relative offset
        if (ch, offset) in self.active_periodic_grants:
            return False
        # 2. Check if a Data burst owns this absolute time slot
        absolute_slot_time = self._get_absolute_slot_time(current_time, offset)
        if (ch, absolute_slot_time) in self.active_aperiodic_grants:
            return False
        return True

    def allocate_data_channel(self, ue_id, current_time, is_periodic, num_packets=1):
        """Allocates a data resource (Channel 2-9) at a specific Uplink time offset (10-19)."""
        # 1. First, clear out any expired Aperiodic grants to free up space
        self._cleanup_expired_aperiodic_grants(current_time)
        allocated_grants = []
        # 2. Search for a free (Subchannel, Time_Offset) combination
        if is_periodic:
            self.release_data_channel(ue_id)
            for ch in range(config.RESERVED_CP, self.num_subchannels):
                for offset in range(config.TDD_DL_MS, config.TDD_FRAME_MS):
                    if self.is_slot_free(ch, offset, current_time):
                        self.active_periodic_grants[(ch, offset)] = {
                            "ue_id": ue_id,
                            "is_periodic": True
                        }
                        return [{"subchannel": ch, "offset": offset}]
            return []
        else:
            # --- DYNAMIC GRANT LOGIC (Find contiguous slots for the burst) ---
            for ch in range(config.RESERVED_CP, self.num_subchannels):
                for offset in range(config.TDD_DL_MS, config.TDD_FRAME_MS):
                    if self.is_slot_free(ch, offset, current_time):
                        absolute_slot_time = self._get_absolute_slot_time(current_time, offset)
                        expires = current_time + (num_packets * config.TDD_FRAME_MS) + (config.TDD_FRAME_MS * 2)
                        self.active_aperiodic_grants[(ch, absolute_slot_time)] = {
                            "ue_id": ue_id,
                            "expires_at": expires,
                            "is_periodic": False
                        }
                        allocated_grants.append(
                        {   "subchannel": ch, 
                            "offset": offset, 
                            "absolute_time": absolute_slot_time
                        })
                        if len(allocated_grants) == num_packets:
                            return allocated_grants
            return allocated_grants

    def release_data_channel(self, ue_id):
        """Explicitly frees a data channel (used when a VoIP call ends or BSR=0)."""
        keys_to_delete = []
        for resource_key, grant in self.active_periodic_grants.items():
            if grant["ue_id"] == ue_id:
                keys_to_delete.append(resource_key)
        for key in keys_to_delete:
            del self.active_periodic_grants[key]

    def _cleanup_expired_aperiodic_grants(self, current_time):
        """Internal helper to garbage collect expired aperiodic (data burst) grants."""
        keys_to_delete = []
        for resource_key, grant in self.active_aperiodic_grants.items():
            if current_time >= grant["expires_at"]:
                keys_to_delete.append(resource_key)
        for key in keys_to_delete:
            del self.active_aperiodic_grants[key]

    def _get_absolute_slot_time(self, current_time, offset):
        """Calculates the true future absolute millisecond for a given frame offset."""
        frame_start = (current_time // config.TDD_FRAME_MS) * config.TDD_FRAME_MS
        if (current_time % config.TDD_FRAME_MS) > offset:
            frame_start += config.TDD_FRAME_MS
        return frame_start + offset