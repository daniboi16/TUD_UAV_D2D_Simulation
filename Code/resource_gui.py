from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollBar
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont
import config

class ResourcePoolCanvas(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(130)
        self.num_subchannels = config.NUM_SUBCHANNELS     
        self.time_window_size = 1000
        self.current_sim_time = 0     
        self.scroll_offset = 0
        self.resource_grid = {}
        self.color_uav = QColor("#3498db")       # Blue for any UAV
        self.color_gue = QColor("#2ecc71")       # Green for any GUE
        self.color_collision = QColor("#e74c3c") # Red for Collisions
        self.color_hd_collision = QColor("#ffa600") # Orange for half collision
        self.color_default = QColor("#95a5a6")   # Gray fallback

    def add_allocation(self, time_slot, subchannel, node_id, is_collision=False):
        if is_collision:
            self.resource_grid[(time_slot, subchannel)] = "COLLISION"
        else:
            if (time_slot, subchannel) in self.resource_grid:
                 self.resource_grid[(time_slot, subchannel)] = "COLLISION"
            else:
                 self.resource_grid[(time_slot, subchannel)] = node_id

    def update_allocation_status(self, time_slot, subchannel, new_status):
        """Overwrites an existing block if a downstream error (like HD) occurs."""
        if (time_slot, subchannel) in self.resource_grid:
            if self.resource_grid[(time_slot, subchannel)] != "COLLISION":
                self.resource_grid[(time_slot, subchannel)] = new_status

    def wheelEvent(self, event):
        """Zooms the timeline in and out using the mouse wheel."""
        if event.angleDelta().y() > 0:
            self.time_window_size = max(50, int(self.time_window_size * 0.8))
        else:
            self.time_window_size = min(5000, int(self.time_window_size * 1.2))
        parent_widget = self.parentWidget()
        if parent_widget and hasattr(parent_widget, 'update_scrollbar_limits'):
            parent_widget.update_scrollbar_limits()
        self.update()

    def set_scroll_offset(self, offset):
        """Called when the user moves the scrollbar."""
        self.scroll_offset = offset
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = self.width()
        height = self.height()
        margin_left = 40
        margin_bottom = 20
        grid_width = width - margin_left
        grid_height = height - margin_bottom
        cell_w = grid_width / self.time_window_size
        cell_h = grid_height / self.num_subchannels
        painter.fillRect(0, 0, width, height, QColor("#1e1e1e")) 
        # Draw Y-axis (Channels)
        painter.setPen(QPen(QColor("#444444"), 1))
        painter.setFont(QFont("Arial", 8))
        for y in range(self.num_subchannels):
            y_pos = int(y * cell_h)
            painter.drawLine(margin_left, y_pos, width, y_pos)
            painter.setPen(QColor("#aaaaaa"))
            painter.drawText(5, int(y_pos + cell_h/2 + 4), f"Ch {self.num_subchannels - y - 1}")
            painter.setPen(QPen(QColor("#444444"), 1))
        # X-axis (Time Slots)
        start_time = self.scroll_offset
        label_interval = 100 
        for x in range(self.time_window_size + 1):
            if (start_time + x) % 10 == 0: 
                x_pos = int(margin_left + x * cell_w)
                if (start_time + x) % label_interval == 0:
                    painter.setPen(QPen(QColor("#666666"), 1))
                    painter.drawLine(x_pos, 0, x_pos, grid_height)
                    painter.setPen(QColor("#aaaaaa"))
                    painter.drawText(x_pos - 15, height - 5, str(int(start_time + x)))
                else:
                    painter.setPen(QPen(QColor("#333333"), 1)) 
                    painter.drawLine(x_pos, 0, x_pos, grid_height)
        # Draw Allocations
        for (t, ch), status in self.resource_grid.items():
            if t >= start_time and t < start_time + self.time_window_size:
                x_idx = t - start_time
                y_idx = (self.num_subchannels - 1) - ch 
                rect = QRectF(margin_left + x_idx * cell_w, y_idx * cell_h, cell_w, cell_h)
                if status == "COLLISION":
                    color = self.color_collision
                elif status == "HD_COLLISION":
                    color = self.color_hd_collision
                elif "UAV" in status:
                    color = self.color_uav
                elif "GUE" in status:
                    color = self.color_gue
                else:
                    color = self.color_default
                painter.setBrush(color)
                painter.setPen(QPen(QColor("#222222"), 1))
                painter.drawRect(QRectF(rect.x(), rect.y(), cell_w, cell_h))

class ResourcePoolWidget(QWidget):
    """A container that holds the Canvas and the Scrollbar together."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        # 1. Create the drawing canvas
        self.canvas = ResourcePoolCanvas()
        # 2. Create the scrollbar
        self.scrollbar = QScrollBar(Qt.Orientation.Horizontal)
        self.scrollbar.setMinimum(0)
        self.scrollbar.setMaximum(0)
        # 3. Connect the scrollbar to the canvas
        self.scrollbar.valueChanged.connect(self.canvas.set_scroll_offset)
        # Add them to the layout
        self.layout.addWidget(self.canvas)
        self.layout.addWidget(self.scrollbar)

    def add_allocation(self, time_slot, subchannel, node_id, is_collision=False):
        """Pass-through function to the canvas."""
        self.canvas.add_allocation(time_slot, subchannel, node_id, is_collision)

    def update_allocation_status(self, time_slot, subchannel, new_status):
        self.canvas.update_allocation_status(time_slot, subchannel, new_status)
    
    def update_scrollbar_limits(self):
        """Recalculates scrollbar max value based on current time and zoom level."""
        is_tracking_latest = self.scrollbar.value() == self.scrollbar.maximum()
        max_scroll = max(0, int(self.canvas.current_sim_time) - self.canvas.time_window_size)
        self.scrollbar.setMaximum(max_scroll)
        if is_tracking_latest:
            self.scrollbar.setValue(max_scroll)

    def update_time(self, current_time):
        """Called every simulation tick to advance the timeline."""
        self.canvas.current_sim_time = current_time
        self.update_scrollbar_limits()
        self.canvas.update()