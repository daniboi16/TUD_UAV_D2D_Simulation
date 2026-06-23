import random, csv, config, time, multiprocessing
import concurrent.futures
from sim_engine import SimulationEngine
from gui import UAVNode, UENode, GNBNode 

# --- BATCH CONFIGURATION ---
NUM_RUNS_PER_CONFIG = 5              # How many times to repeat each scenario
SIMULATION_TIME_MS = 600000          # Run each simulation for 10 mins
GUE_COUNTS_TO_TEST = [20,40,60,80]   # The variables we are sweeping
MODES_TO_TEST = ["BASELINE_U2U", 
    "PROPOSED_U2U", 
    "BASELINE_U2N", 
    "PROPOSED_U2N"]
BASELINE_CSV = "baseline_results.csv"
PROPOSED_CSV = "proposed_results.csv"

def run_headless_simulation(mode, num_gues, run_id, seed_value, file_lock=None):
    """Runs a single instance of the simulation headlessly and returns the stats."""
    random.seed(seed_value)
    # 1. Override config dynamically for this specific run
    config.SIM_MODE = mode
    config.HEADLESS = True
    config.NUM_GUES = num_gues
    config.UNUSED_IP_ADDR = [f"fe80::0200:00ff:fe00:{i:04x}" for i in range(1, num_gues + 10)]
    config.IN_USE_IP_ADDR = []
    # 2. Generate Nodes (Without the GUI Canvas)
    uav = UAVNode("UAV_0", config.UAV_START_POS[0], config.UAV_START_POS[1], config.UAV_START_ALT)
    ues = []
    for i in range(1, num_gues + 1):
        rand_x = random.randint(config.GUE_SPAWN_RANGE_X[0], config.GUE_SPAWN_RANGE_X[1])
        rand_y = random.randint(config.GUE_SPAWN_RANGE_Y[0], config.GUE_SPAWN_RANGE_Y[1])
        ues.append(UENode(f"GUE_{i}", rand_x, rand_y))
    gnb = None
    if "U2N" in mode:
        gnb = GNBNode("gNB_1", config.GNB_POS[0], config.GNB_POS[1], config.GNB_ALT)
    # 3. Initialize the Engine
    sim = SimulationEngine(file_lock=file_lock)
    # 4. Inject "Dummy" Callbacks to prevent GUI crashes
    sim.log_callback = lambda msg: None
    sim.resource_callback = lambda time_slot, subchannel, node_id, is_collision: None
    sim.hd_callback = lambda time_slot, subchannel, new_status: None
    # 5. Start and Run at Max CPU Speed
    if gnb:
        sim.start(uav, ues, gnb)
    else:
        sim.start(uav, ues)
    try:
        sim.env.run(until=SIMULATION_TIME_MS)
    except Exception as e:
        print(f"Simulation Error on {num_gues} UEs, Run {run_id}: {e}")
    # 6. Calculate Final Rates
    s = sim.stats
    now = max(1, sim.env.now)
    total_tx = max(1, s["total_transmissions"])
    # Latency
    avg_e2e = s.get("e2e_delay_sum", 0) / max(1, s.get("e2e_delay_count", 0))
    avg_sched = s.get("scheduling_delay_sum", 0) / max(1, s.get("scheduling_delay_count", 0))
    # Reliability & Rates
    pdr = (s.get("e2e_delay_count", 0) / max(1, s.get("total_generated_data_pkts", 0))) * 100
    throughput_kbps = (s.get("successful_data_bytes", 0) * 8) / now
    # Spectrum Efficiency
    total_possible_blocks = now * config.NUM_SUBCHANNELS
    spectrum_util = (len(sim.spectrum_usage) / total_possible_blocks) * 100
    # Failure Rates
    implicit_fail_rate = (s.get("implicit_link_failures", 0) / max(1, s.get("connection_attempts", 0))) * 100
    admin_reject_rate = (s.get("admission_rejections", 0) / max(1, s.get("connection_attempts", 0))) * 100
    # Collision Analytics
    reg_coll_pct = (s["collisions"] / total_tx) * 100
    hd_coll_pct = (s["half_duplex_collisions"] / total_tx) * 100
    total_coll_pct = reg_coll_pct + hd_coll_pct
    hd_uav_pct = (s["hd_uav_deaf"] / total_tx) * 100
    hd_gue_pct = (s["hd_gue_deaf"] / total_tx) * 100
    # Match the Return Keys exactly to the CSV Headers
    return {
        "Simulation Mode": mode,
        "Number of UEs": num_gues,
        "Run ID": run_id,
        "Random Seed": seed_value,
        "Total Transmissions": s["total_transmissions"],
        "Control Plane Transmissions": s.get("control_plane_tx", 0),
        "User Plane Transmissions": s.get("user_plane_tx", 0),
        "Total Generated Data Packets": s.get("total_generated_data_pkts", 0),
        "Successful Decodes": s["successful_decodes"],
        "Signal to Noise Ratio Failures": s["snr_failures"],
        "Retransmissions Attempted": s.get("retransmissions_attempted", 0),
        "Data Packets Dropped": s["data_packets_dropped"],
        "Voice over IP Packets Dropped": s["voip_packets_dropped"],
        "Total Physical Collisions": s["collisions"],
        "Total Half-Duplex Collisions": s["half_duplex_collisions"],
        "Half-Duplex Collisions (UAV Deaf)": s["hd_uav_deaf"],
        "Half-Duplex Collisions (Ground UE Deaf)": s["hd_gue_deaf"],
        "Post-Setup Physical Collisions": s.get("post_setup_physical_collisions", 0),
        "Post-Setup Half-Duplex Collisions": s.get("post_setup_hd_collisions", 0),
        "Physical Collision Rate (%)": round(reg_coll_pct, 2),
        "Half-Duplex Collision Rate (%)": round(hd_coll_pct, 2),
        "Total Collision Rate (%)": round(total_coll_pct, 2),
        "Half-Duplex UAV Deafness Rate (%)": round(hd_uav_pct, 2),
        "Half-Duplex Ground UE Deafness Rate (%)": round(hd_gue_pct, 2),
        "Average End-to-End Delay (ms)": round(avg_e2e, 2),
        "Average Scheduling Delay (ms)": round(avg_sched, 2),
        "Packet Delivery Ratio (%)": round(pdr, 2),
        "Aggregate Throughput (kbps)": round(throughput_kbps, 2),
        "Spectrum Utilization (%)": round(spectrum_util, 2),
        "Implicit Link Failure Rate (%)": round(implicit_fail_rate, 2),
        "Admission Rejection Rate (%)": round(admin_reject_rate, 2)
    }

def main():
    print(f"Starting Batch Simulation: {len(MODES_TO_TEST)} Modes, {len(GUE_COUNTS_TO_TEST)} Scenarios.")
    start_time = time.time()
    # Define EXACT headers used in run_headless_simulation return dictionary
    headers = [
        # --- Run Configuration ---
        "Simulation Mode", "Number of UEs", "Run ID", "Random Seed",
        # --- Base Transmission Counts ---
        "Total Transmissions", "Control Plane Transmissions", "User Plane Transmissions", 
        "Total Generated Data Packets", "Successful Decodes", "Signal to Noise Ratio Failures", 
        "Retransmissions Attempted", "Data Packets Dropped", "Voice over IP Packets Dropped",
        # --- Collision Counts ---
        "Total Physical Collisions", "Total Half-Duplex Collisions", 
        "Half-Duplex Collisions (UAV Deaf)", "Half-Duplex Collisions (Ground UE Deaf)",
        "Post-Setup Physical Collisions", "Post-Setup Half-Duplex Collisions",
        # --- Percentages ---
        "Physical Collision Rate (%)", "Half-Duplex Collision Rate (%)", "Total Collision Rate (%)", 
        "Half-Duplex UAV Deafness Rate (%)", "Half-Duplex Ground UE Deafness Rate (%)",
        # --- Latencies ---
        "Average End-to-End Delay (ms)", "Average Scheduling Delay (ms)",
        # --- System Performance ---
        "Packet Delivery Ratio (%)", "Aggregate Throughput (kbps)", "Spectrum Utilization (%)", 
        "Implicit Link Failure Rate (%)", "Admission Rejection Rate (%)"
    ]
    # Initialize BOTH files with headers
    for filename in [BASELINE_CSV, PROPOSED_CSV]:
        with open(filename, 'w', newline='') as f:
            csv.DictWriter(f, fieldnames=headers).writeheader()

    with multiprocessing.Manager() as manager:  
        file_lock = manager.Lock() # Create the cross-process lock
        # 1. Build a list of all the tasks we need to run
        tasks = []
        for num_gues in GUE_COUNTS_TO_TEST:
            for run in range(1, NUM_RUNS_PER_CONFIG + 1):
                shared_seed = (num_gues * 1000) + run
                for mode in MODES_TO_TEST:
                    tasks.append((mode, num_gues, run, shared_seed, file_lock))
        print(f"Executing {len(tasks)} total simulations in parallel...")

        # 2. Fire up the Process Pool (Automatically uses all available CPU cores)
        with concurrent.futures.ProcessPoolExecutor() as executor:
            # Submit all tasks to the pool
            futures = {executor.submit(run_headless_simulation, *task): task for task in tasks}
            # 3. As each individual simulation finishes, grab its data and write to CSV
            for future in concurrent.futures.as_completed(futures):
                task = futures[future]
                mode, num_gues, run_id, _, _ = task
                target_file = BASELINE_CSV if "BASELINE" in mode else PROPOSED_CSV
                try:
                    result = future.result()
                    with open(target_file, 'a', newline='') as f:
                        csv.DictWriter(f, fieldnames=headers).writerow(result)
                    print(f"Completed [{mode}] UEs: {num_gues} Run: {run_id}/{NUM_RUNS_PER_CONFIG} - Saved.")
                except Exception as e:
                    print(f"Simulation crashed for [{mode}] UEs: {num_gues} Run: {run_id} -> {e}")
        elapsed = time.time() - start_time
        print(f"\nBatch completed in {elapsed/60:.2f} minutes.")

if __name__ == "__main__":
    main()