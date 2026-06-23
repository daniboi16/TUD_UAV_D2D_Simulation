import config, random
from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import Qt, QPointF, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QPixmap
from protocols import UAVState, UEState
from scheduler import UAVScheduler

class Node:
    """Base class for all network elements in the simulation."""
    def __init__(self, node_id, x, y, alt, node_type, state):
        self.pos = QPointF(x, y) # 2D Grid Position
        self.alt = alt           # 3D Altitude
        self.id = node_id        # e.g., "UAV_0" or "GUE_1" 
        self.node_type = node_type # "UAV Relay" or "Ground UE"
        self.status = state
        self.gnss_available = True # Used for Sync
        self.last_discovery_time = -config.DISCOVERY_FREQUENCY 
        self.connected_to = {}

class UAVNode(Node):
    """Represents the Aerial Relay platform."""
    def __init__(self, node_id="UAV_0", x=0, y=0, alt=150):
        super().__init__(node_id, x, y, alt, "UAV Relay", UAVState.IDLE)
        self.local_ip_address = config.UAV_IPV6
        self.scheduler = UAVScheduler(config.NUM_SUBCHANNELS)
        self.last_heartbeat_rx = {}
        self.tx_buffer = []     
        self.data_tx_buffer = [] 
        self.dl_ch_idx = config.RESERVED_CP
        self.gue_telemetry = {}     # Format: { "GUE_1": {"x": 100, "y": -200, "rsrp": -85.0}, ... }
       
class UENode(Node):
    """Represents a Ground User Equipment (GUE)."""
    def __init__(self, node_id, x, y):
        super().__init__(node_id, x, y, 0, "Ground UE", UEState.IDLE)
        self.dns_cache = {}
        self.sps_config = None
        self.active_grant = None

class GNBNode(Node):
    """Represents the operational Terrestrial Base Station (Core Network Gateway)."""
    def __init__(self, node_id="gNB_1", x=0, y=0, alt=50):
        super().__init__(node_id, x, y, alt, "Base Station", "OPERATIONAL")
        self.local_ip_address = config.GNB_IPV6

class DroneCanvas(QWidget):
    nodeSelected = pyqtSignal(object)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.pan_offset = QPointF(0, 0)  # The grid coordinate currently at the center of the screen
        self.last_mouse_pos = None       # Tracks the mouse during a drag
        self.is_panning = False          # True when the user is dragging the background
        self.grid_step = config.GRID_STEP_SIZE 
        self.view_mode = "2D"
        self.meters_per_pixel = config.METERS_PER_PIXEL
        self.uav = UAVNode("UAV_0", config.UAV_START_POS[0], config.UAV_START_POS[1], config.UAV_START_ALT)
        self.ues = []
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"]:
            self.gnb = GNBNode("gNB_1", config.GNB_POS[0], config.GNB_POS[1], config.GNB_ALT)
        if config.SIM_MODE == "POSITIONING_TEST":
            random.seed(42)
            for i in range(1, config.NUM_GUES + 1):
                rand_x = random.gauss(config.GUE_SPAWN_CENTER_X, config.GUE_SPAWN_SPREAD)
                rand_y = random.gauss(config.GUE_SPAWN_CENTER_Y, config.GUE_SPAWN_SPREAD)
                new_ue = UENode(f"GUE_{i}", rand_x, rand_y)
                self.ues.append(new_ue)
        else:
            for i in range(1, config.NUM_GUES + 1):
                rand_x = random.randint(config.GUE_SPAWN_RANGE_X[0], config.GUE_SPAWN_RANGE_X[1])
                rand_y = random.randint(config.GUE_SPAWN_RANGE_Y[0], config.GUE_SPAWN_RANGE_Y[1])
                new_ue = UENode(f"GUE_{i}", rand_x, rand_y)
                self.ues.append(new_ue)
        self.selected_node = None
        self.active_node = None
        self.uav_icon = QPixmap("UAV.png").scaled(65, 65, Qt.AspectRatioMode.KeepAspectRatio)
        self.gue_icon = QPixmap("GUE.png").scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio)
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"]:
            self.gnb_icon = QPixmap("gNB.png").scaled(70, 70, Qt.AspectRatioMode.KeepAspectRatio)

    def to_screen(self, grid_pos):
        """Converts grid coordinates (0,0 center) to screen pixels."""
        center = self.rect().center()
        screen_x = center.x() + ((grid_pos.x() - self.pan_offset.x()) / self.meters_per_pixel)
        screen_y = center.y() - ((grid_pos.y() - self.pan_offset.y()) / self.meters_per_pixel)
        return QPointF(screen_x, screen_y)

    def from_screen(self, screen_pos):
        """Converts screen pixels to grid coordinates."""
        center = self.rect().center()
        grid_x = self.pan_offset.x() + (screen_pos.x() - center.x()) * self.meters_per_pixel
        grid_y = self.pan_offset.y() + (center.y() - screen_pos.y()) * self.meters_per_pixel
        max_x = (self.width() / 2) * self.meters_per_pixel
        max_y = (self.height() / 2) * self.meters_per_pixel
        clamped_x = max(-max_x, min(grid_x, max_x))
        clamped_y = max(-max_y, min(grid_y, max_y))
        return QPointF(clamped_x, clamped_y)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        origin_screen = self.to_screen(QPointF(0, 0))
        pen = QPen(QColor("#dcdde1"), 1)
        painter.setPen(pen)        
        # Vertical lines
        start_x = int(origin_screen.x() % self.grid_step)
        for x in range(start_x, self.width(), self.grid_step):
            painter.drawLine(x, 0, x, self.height())
        # Horizontal lines
        start_y = int(origin_screen.y() % self.grid_step)
        for y in range(start_y, self.height(), self.grid_step):
            painter.drawLine(0, y, self.width(), y)
        # Draw Axes (Origin)
        pen.setColor(QColor("#7f8c8d"))
        pen.setWidth(2)
        painter.setPen(pen)
        if 0 <= origin_screen.x() <= self.width():
            painter.drawLine(int(origin_screen.x()), 0, int(origin_screen.x()), self.height())
        if 0 <= origin_screen.y() <= self.height():
            painter.drawLine(0, int(origin_screen.y()), self.width(), int(origin_screen.y()))
        uav_w, uav_h = 65, 65
        gue_w, gue_h = 40, 40
        #  Draw UAV (PNG at Grid 0,0)
        uav_screen = self.to_screen(self.uav.pos)
        painter.drawPixmap(int(uav_screen.x() - uav_w/2), int(uav_screen.y() - uav_h/2), self.uav_icon)
        painter.setPen(QColor("#2c3e50"))
        uav_txt = f"UAV ({int(self.uav.pos.x())}, {int(self.uav.pos.y())}, {int(self.uav.alt)})"
        painter.drawText(int(uav_screen.x() - uav_w/2), int(uav_screen.y() - uav_h/2 - 5), uav_txt)
        # Draw UAV range bubble
        uav_screen = self.to_screen(self.uav.pos)
        pixel_radius = config.UAV_COMM_RANGE / self.meters_per_pixel
        painter.setPen(QPen(QColor(52, 152, 219, 150), 2, Qt.PenStyle.DashLine))
        painter.setBrush(QColor(52, 152, 219, 30))
        painter.drawEllipse(uav_screen, pixel_radius, pixel_radius)
        #  Draw GUEs
        for ue in self.ues:
            ue_screen = self.to_screen(ue.pos)
            painter.drawPixmap(int(ue_screen.x() - gue_w/2), int(ue_screen.y() - gue_h/2), self.gue_icon)
            painter.setPen(QColor("#2c3e50"))
            coords = f"({int(ue.pos.x())}, {int(ue.pos.y())}, {int(ue.alt)})"
            painter.drawText(int(ue_screen.x() + gue_w/2 + 5), int(ue_screen.y() + 5), f"{ue.id} {coords}")
            if ue.status == UEState.CONNECTED:
                uav_s = self.to_screen(self.uav.pos)
                ue_s = self.to_screen(ue.pos)
                pen = QPen(QColor("#2ecc71"), 2, Qt.PenStyle.SolidLine)
                painter.setPen(pen)
                painter.drawLine(uav_s, ue_s)
                painter.setBrush(QColor(46, 204, 113, 50))
                painter.drawEllipse(ue_s, 20, 20)
        # Draw gNB
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"]:
            gnb_w, gnb_h = 70, 70
            gnb_screen = self.to_screen(self.gnb.pos)
            painter.drawPixmap(int(gnb_screen.x() - gnb_w/2), int(gnb_screen.y() - gnb_h/2), self.gnb_icon)
            painter.setPen(QColor("#2c3e50"))
            gnb_txt = f"{self.gnb.id} ({int(self.gnb.pos.x())}, {int(self.gnb.pos.y())}, {int(self.gnb.alt)})"
            painter.drawText(int(gnb_screen.x() - gnb_w/2), int(gnb_screen.y() + gnb_h/2 + 15), gnb_txt)
            # Draw the Uu Backhaul Link if we are in U2N Mode
            if self.gnb.status == "CONNECTED":
                pen = QPen(QColor("#8e44ad"), 2, Qt.PenStyle.DashDotLine) 
                painter.setPen(pen)
                painter.drawLine(uav_screen, gnb_screen)
    
    def mousePressEvent(self, event):
        click_pos = event.position()
        self.last_mouse_pos = event.position()
        # 1. Check UAV 
        uav_screen_pos = self.to_screen(self.uav.pos)
        # Use a pixel threshold 
        if (click_pos - uav_screen_pos).manhattanLength() < 40:
            self.active_node = self.uav
            self.selected_node = self.uav
            self.nodeSelected.emit(self.active_node)
            self.update()
            return
        if config.SIM_MODE in ["BASELINE_U2N", "PROPOSED_U2N"]:
        # 2. Check gNB
            gNB_screen_pos = self.to_screen(self.gnb.pos)
            if (click_pos - gNB_screen_pos).manhattanLength() < 40:
                self.active_node = self.gnb
                self.selected_node = self.gnb
                self.nodeSelected.emit(self.active_node)
                self.update()
                return
        # 3. Check UEs 
        for ue in self.ues:
            ue_screen_pos = self.to_screen(ue.pos)
            # Use a pixel threshold 
            if (click_pos - ue_screen_pos).manhattanLength() < 30:
                self.active_node = ue
                self.selected_node = ue
                self.nodeSelected.emit(self.active_node)
                self.update()
                return
        if event.button() in [Qt.MouseButton.LeftButton, Qt.MouseButton.RightButton, Qt.MouseButton.MiddleButton]:
            self.is_panning = True
            
    def mouseMoveEvent(self, event):
        current_pos = event.position()
        if self.selected_node:
            self.selected_node.pos = self.from_screen(event.position())
        elif self.is_panning and self.last_mouse_pos:
            delta = current_pos - self.last_mouse_pos
            # Convert pixel delta to grid delta (invert X due to coordinate system)
            dx = -delta.x() * self.meters_per_pixel
            dy = delta.y() * self.meters_per_pixel
            self.pan_offset += QPointF(dx, dy)
            self.last_mouse_pos = current_pos
        self.update()

    def mouseReleaseEvent(self, event):
        self.selected_node = None
        self.is_panning = False

    def zoom_in(self):
        """Decreases meters per pixel (zooms in)."""
        self.meters_per_pixel = max(1.0, self.meters_per_pixel * 0.8) # Limit zoom in
        self.update()

    def zoom_out(self):
        """Increases meters per pixel (zooms out)."""
        self.meters_per_pixel = min(500.0, self.meters_per_pixel * 1.2) # Limit zoom out
        self.update()

    def wheelEvent(self, event):
        """Zoom toward the mouse cursor position."""
        mouse_pos = event.position()
        # 1. Record the logical grid coordinate currently under the mouse
        grid_before = self.from_screen(mouse_pos)
        # 2. Adjust the Zoom scale
        zoom_factor = 0.8 if event.angleDelta().y() > 0 else 1.25
        self.meters_per_pixel = max(1.0, min(500.0, self.meters_per_pixel * zoom_factor))
        # 3. Adjust the pan_offset so that the original grid coordinate 
        # remains exactly under the current mouse position.
        center = self.rect().center()
        self.pan_offset = grid_before - QPointF(
            (mouse_pos.x() - center.x()) * self.meters_per_pixel,
            (center.y() - mouse_pos.y()) * self.meters_per_pixel
        )
        self.update()