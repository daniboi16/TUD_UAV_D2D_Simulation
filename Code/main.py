# main.py
import sys, csv
from PyQt6 import uic
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHeaderView, QTableWidgetItem
from PyQt6.QtCore import Qt, QTimer, QPointF
from PyQt6.QtGui import QShortcut, QKeySequence

from sim_engine import SimulationEngine
from gui import DroneCanvas
from resource_gui import ResourcePoolWidget
import config

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("Layout.ui", self)
        self.setWindowTitle("Thesis Simulation: UAV D2D Operational Model")
        self.resize(1400, 800)
        self.is_running = False
        self.actionStart.triggered.connect(self.start_simulation)
        self.actionPause.triggered.connect(self.toggle_play_pause)
        self.actionRestart.triggered.connect(self.restart_simulation)
        self.actionExit.triggered.connect(self.close)
        self.actionUnselect_Message.triggered.connect(self.clear_message_selection)
        self.actionClear_Log.triggered.connect(self.clear_log_table)

        #Drawing Drone Canvas
        self.canvas_layout = self.canvas.layout()
        self.real_canvas = DroneCanvas()
        self.canvas_layout.addWidget(self.real_canvas)
        self.real_canvas.nodeSelected.connect(self.update_node_info)
        self.current_selected_node = None
        self.update_node_info(self.real_canvas.uav)
        self.NodeGNSSBox.stateChanged.connect(self.sync_gnss_box_to_node)
        QShortcut(QKeySequence.StandardKey.ZoomIn, self).activated.connect(self.real_canvas.zoom_in)
        QShortcut(QKeySequence.StandardKey.ZoomOut, self).activated.connect(self.real_canvas.zoom_out)

        #Drawing Resource Canvas
        if self.resource_container.layout() is None:
            self.resource_container.setLayout(QVBoxLayout())
        self.resource_canvas_layout = self.resource_container.layout()
        self.resource_canvas = ResourcePoolWidget()
        self.resource_canvas_layout.addWidget(self.resource_canvas)

        #Filter Initializations
        self.NodeFilter.currentTextChanged.connect(self.apply_log_filters)
        self.SourceFilter.currentTextChanged.connect(self.apply_log_filters)
        self.PlaneFilter.currentTextChanged.connect(self.apply_log_filters)
        self.MsgFilter.currentTextChanged.connect(self.apply_log_filters)
        self.init_filter_options()

        #Log connect
        self.log.itemClicked.connect(self.display_message_details)
        self.clear_message_selection()        
        header = self.log.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)       # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive) # Node
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive) # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)       # Plane
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.log.setColumnWidth(0, 80)  # Time column width
        self.log.setColumnWidth(3, 90)  # Plane column width
        self.SimTimer = QTimer()
        self.SimTimer.timeout.connect(self.update_sim)
        
    def start_simulation(self):
        """Initializes the SimPy processes and starts the timer."""
        if not self.is_running:
            self.sim = SimulationEngine()
            self.sim.log_callback = self.add_log_entry
            self.sim.resource_callback = self.resource_canvas.add_allocation
            self.sim.hd_callback = self.resource_canvas.update_allocation_status
            if "U2N" in config.SIM_MODE:
                self.sim.start(self.real_canvas.uav, self.real_canvas.ues, self.real_canvas.gnb)
            else:
                self.sim.start(self.real_canvas.uav, self.real_canvas.ues)
            self.SimTimer.start(config.SIM_STEP)
            self.is_running = True

    def toggle_play_pause(self):
        """Pauses or resumes the QTimer."""
        if self.SimTimer.isActive():
            self.SimTimer.stop()
            if hasattr(self, 'sim') and self.sim is not None and not config.HEADLESS:
                self.sim.export_stats_to_csv("thesis_d2d_results.csv")
                self.export_log_to_csv("gui_message_log.csv")
                if config.SIM_MODE == "POSITIONING_TEST":
                    self.sim.export_time_series_to_csv()
                print("Simulation Paused. Data Exported.")
        else:
            self.SimTimer.start(config.SIM_STEP)

    def restart_simulation(self):
        """Resets the simulation engine and clears the log table."""
        self.SimTimer.stop()
        self.is_running = False
        self.real_canvas.uav.pos = QPointF(0, 0)
        for ue in self.real_canvas.ues:
            ue.status = "IDLE"
            ue.app_state = "IDLE"
            ue.connected_to = None
            ue.dns_cache = {}
            ue.sps_config = None
            ue.active_grant = None
        if hasattr(self.resource_canvas, 'allocations'):
            self.resource_canvas.allocations.clear()
            self.resource_canvas.update()
        self.clear_log_table()
        self.real_canvas.update()

    def update_sim(self):
        """Advances SimPy environment and refreshes the canvas."""
        next_step_time = self.sim.env.now + config.SIM_STEP
        self.sim.run_step(until=next_step_time)
        self.real_canvas.update()
        self.resource_canvas.update_time(self.sim.env.now)

    def update_node_info(self, node_data):
        """Updates the Node Selected box labels based on backend data."""
        self.NodeGNSSBox.blockSignals(True)
        self.current_selected_node = node_data
        self.NodeTypeData.setText(node_data.node_type)
        self.NodeNameData.setText(node_data.id) 
        self.NodeStatusData.setText(node_data.status) 
        self.NodeGNSSBox.setChecked(node_data.gnss_available)
        self.NodeGNSSBox.blockSignals(False)
        
    def sync_gnss_box_to_node(self):
        """Handler to update the backend Node object when GUI checkbox changes."""
        if self.current_selected_node:
            new_val = self.NodeGNSSBox.isChecked()
            self.current_selected_node.gnss_available = new_val
    
    def row_matches_filter(self, msg_obj):
        """Helper: Checks if a message object matches the current dropdown filters."""
        selected_node = self.NodeFilter.currentText()
        selected_source = self.SourceFilter.currentText()
        selected_plane = self.PlaneFilter.currentText()
        selected_msg = self.MsgFilter.currentText()
        node_match = (selected_node == "All Nodes" or selected_node == msg_obj.node_id)
        source_match = (selected_source == "All Nodes" or selected_source == msg_obj.source_id)
        plane_match = (selected_plane == "All Planes" or selected_plane == msg_obj.plane)
        msg_match = (selected_msg == "All Messages" or selected_msg == msg_obj.msg_type)
        return node_match and source_match and plane_match and msg_match

    def add_log_entry(self, msg_obj):
        row = self.log.rowCount()
        self.log.insertRow(row)
        self.log.setItem(row, 0, QTableWidgetItem(f"{msg_obj.time:.0f} ms"))
        self.log.setItem(row, 1, QTableWidgetItem(msg_obj.node_id))
        self.log.setItem(row, 2, QTableWidgetItem(msg_obj.source_id))
        self.log.setItem(row, 3, QTableWidgetItem(msg_obj.plane))
        self.log.setItem(row, 4, QTableWidgetItem(msg_obj.msg_type))
        self.log.item(row, 0).setData(Qt.ItemDataRole.UserRole, msg_obj) # Store the actual object in the first cell of the row for retrieval
        if not self.row_matches_filter(msg_obj):
            self.log.setRowHidden(row, True)
        if not self.log.isRowHidden(row):
            self.log.scrollToBottom()
    
    def display_message_details(self, item): 
        """Retrieves the hidden Message object and displays its internal layers."""
        row_idx = item.row()
        msg_obj = self.log.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        plane_color = "#e67e22" if msg_obj.plane == "Control" else "#2ecc71" # Color coding for Plane distinction
        html = f"""
        <div style="font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; color: #ffffff;">
            <h3 style="color: {plane_color}; margin-bottom: 5px;">
                {msg_obj.plane.upper()} PLANE: {msg_obj.msg_type} (Msg #{row_idx + 1})
            </h3>
            <hr style="border: 0; border-top: 1px solid #444;">
        """
        for layer, params in msg_obj.stack.items():
            if params: # Only display layers that have data
                html += f"<b style='color: #3498db; text-transform: uppercase;'>{layer} LAYER</b><br>"
                for key, val in params.items():
                    html += f"&nbsp;&nbsp;<span style='color: #bdc3c7;'>• {key}:</span> "
                    html += f"<span style='color: #f1c40f;'>{val}</span><br>"
                html += "<br>"
        html += "</div>"
        self.MsgDetailBox.setHtml(html)

    def apply_log_filters(self):
        """Filters the log table based on both Node and Message type selections."""
        for row in range(self.log.rowCount()):
            msg_obj = self.log.item(row, 0).data(Qt.ItemDataRole.UserRole)
            should_show = self.row_matches_filter(msg_obj)
            self.log.setRowHidden(row, not should_show)
            
    def init_filter_options(self):
        """Initializes dropdown filters with all 3GPP messages and nodes."""
        self.NodeFilter.clear()
        self.SourceFilter.clear()
        node_list = ["All Nodes", self.real_canvas.uav.id]
        source_list = ["All Nodes", "Transmitted", self.real_canvas.uav.id]
        for ue in self.real_canvas.ues:
            node_list.append(ue.id)
            source_list.append(ue.id)
        self.NodeFilter.addItems(node_list)
        self.SourceFilter.addItems(source_list)

        self.MsgFilter.clear()
        self.MsgFilter.addItems([
            "All Messages",
            "Discovery Announcement",
            "Direct Communication Request",
            "Direct Security Mode Command",
            "Direct Security Mode Complete",
            "Direct Communication Accept",
            "Router Solicitation",
            "Router Advertisement",
            "DNS Query",
            "DNS Response",
            "UAV Relay Data",
            "Status Report",
            "Resource Request",
            "Resource Grant",
            "Data ACK",
            "Link Release",
            "Release ACK",
            "System Information Broadcast"
            "RRC Setup Request",
            "RRC Setup",
            "RRC Setup Complete",
            "Security Mode Command",
            "Security Mode Complete",
            "PDU Request",
            "RRC Reconfig",
            "RRC Reconfig Complete",
            "UE Report",
            "UE Report Ack"
        ])

    def clear_message_selection(self):
        """Resets the inspector to the 'No Message Selected' state."""
        self.log.clearSelection()
        placeholder_html = """
        <div style='margin-top: 50px; text-align: center; color: #7f8c8d; font-family: Arial;'>
            <h3>No Message Selected</h3>
            <p>Select a log entry to view 3GPP protocol stack details.</p>
        </div>
        """
        self.MsgDetailBox.setHtml(placeholder_html)
        
    def clear_log_table(self):
        """Clears all entries from the log table and resets selection."""
        self.log.setRowCount(0)
        self.clear_message_selection()
    
    def export_log_to_csv(self, filename="gui_message_log.csv"):
        """Exports the content of the GUI log table to a CSV file."""
        try:
            with open(filename, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Time", "Node", "Source", "Plane", "Message Type"])
                for row in range(self.log.rowCount()):
                    time_val = self.log.item(row, 0).text() if self.log.item(row, 0) else ""
                    node_val = self.log.item(row, 1).text() if self.log.item(row, 1) else ""
                    source_val = self.log.item(row, 2).text() if self.log.item(row, 2) else ""
                    plane_val = self.log.item(row, 3).text() if self.log.item(row, 3) else ""
                    msg_type_val = self.log.item(row, 4).text() if self.log.item(row, 4) else ""
                    writer.writerow([time_val, node_val, source_val, plane_val, msg_type_val])
        except Exception as e:
            print(f"Failed to export log to CSV: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())