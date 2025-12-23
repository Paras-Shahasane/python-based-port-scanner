#!/usr/bin/env python3
"""
Ethical TCP Port Scanner
A GUI-based network port scanner for legitimate security auditing.
Uses only standard Python libraries for scanning functionality.

LEGAL NOTICE: Only scan networks and systems you own or have explicit 
written permission to test. Unauthorized port scanning may be illegal.
"""

import sys
import socket
import threading
from queue import Queue
from typing import List, Tuple

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QGroupBox, QSpinBox
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QPalette, QColor
except ImportError:
    print("PyQt5 not found. Install with: pip install PyQt5")
    sys.exit(1)


class PortScanner:
    """Core scanning logic using standard socket library."""
    
    def __init__(self, target: str, start_port: int, end_port: int, timeout: float = 1.0):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.open_ports: List[int] = []
        self.stop_flag = False
        
    def resolve_target(self) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Unable to resolve hostname: {self.target}")
    
    def scan_port(self, port: int) -> Tuple[int, bool]:
        """
        Scan a single port using TCP connect method.
        Returns: (port_number, is_open)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return (port, result == 0)
        except Exception:
            return (port, False)
    
    def scan_ports_threaded(self, progress_callback=None, max_threads=50):
        """
        Scan ports using a thread pool for efficiency.
        Uses a queue-based approach for controlled threading.
        """
        self.open_ports = []
        port_queue = Queue()
        
        # Populate queue with ports to scan
        for port in range(self.start_port, self.end_port + 1):
            port_queue.put(port)
        
        def worker():
            while not port_queue.empty() and not self.stop_flag:
                try:
                    port = port_queue.get(timeout=0.1)
                    port_num, is_open = self.scan_port(port)
                    
                    if is_open:
                        self.open_ports.append(port_num)
                    
                    if progress_callback:
                        progress_callback(port_num, is_open)
                    
                    port_queue.task_done()
                except Exception:
                    pass
        
        # Create and start worker threads
        threads = []
        num_threads = min(max_threads, self.end_port - self.start_port + 1)
        
        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        return sorted(self.open_ports)
    
    def stop(self):
        """Signal the scanner to stop."""
        self.stop_flag = True


class ScanThread(QThread):
    """Qt thread for running port scan without blocking GUI."""
    
    progress = pyqtSignal(int, bool)  # port, is_open
    finished = pyqtSignal(list)  # list of open ports
    error = pyqtSignal(str)  # error message
    
    def __init__(self, target: str, start_port: int, end_port: int):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.scanner = None
    
    def run(self):
        """Execute the port scan in a separate thread."""
        try:
            self.scanner = PortScanner(self.target, self.start_port, self.end_port)
            ip = self.scanner.resolve_target()
            self.progress.emit(-1, False)  # Signal resolution complete
            
            open_ports = self.scanner.scan_ports_threaded(
                progress_callback=lambda p, o: self.progress.emit(p, o),
                max_threads=50
            )
            
            self.finished.emit(open_ports)
        except Exception as e:
            self.error.emit(str(e))
    
    def stop(self):
        """Stop the scanning process."""
        if self.scanner:
            self.scanner.stop()


class PortScannerGUI(QMainWindow):
    """Main GUI application window."""
    
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Ethical TCP Port Scanner")
        self.setGeometry(100, 100, 700, 600)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Legal warning
        warning_label = QLabel(
            "⚠️ LEGAL WARNING: Only scan networks you own or have written permission to test."
        )
        warning_label.setStyleSheet("color: #d32f2f; font-weight: bold; padding: 10px; background: #ffebee; border-radius: 5px;")
        warning_label.setWordWrap(True)
        main_layout.addWidget(warning_label)
        
        # Input section
        input_group = QGroupBox("Scan Configuration")
        input_layout = QVBoxLayout()
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target (IP/Domain):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.1 or localhost")
        target_layout.addWidget(self.target_input)
        input_layout.addLayout(target_layout)
        
        # Port range inputs
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Start Port:"))
        self.start_port_input = QSpinBox()
        self.start_port_input.setRange(1, 65535)
        self.start_port_input.setValue(1)
        port_layout.addWidget(self.start_port_input)
        
        port_layout.addWidget(QLabel("End Port:"))
        self.end_port_input = QSpinBox()
        self.end_port_input.setRange(1, 65535)
        self.end_port_input.setValue(1024)
        port_layout.addWidget(self.end_port_input)
        input_layout.addLayout(port_layout)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 10px;")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.setStyleSheet("padding: 10px;")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("font-weight: bold; padding: 8px; background: #e3f2fd; border-radius: 5px;")
        main_layout.addWidget(self.status_label)
        
        # Results area
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier", 10))
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group)
    
    def validate_inputs(self) -> Tuple[bool, str]:
        """Validate user inputs."""
        target = self.target_input.text().strip()
        if not target:
            return False, "Please enter a target IP or domain"
        
        start = self.start_port_input.value()
        end = self.end_port_input.value()
        
        if start > end:
            return False, "Start port must be less than or equal to end port"
        
        if end - start > 10000:
            return False, "Port range too large (max 10,000 ports)"
        
        return True, ""
    
    def start_scan(self):
        """Start the port scanning process."""
        valid, error_msg = self.validate_inputs()
        if not valid:
            self.results_text.append(f"❌ Error: {error_msg}\n")
            return
        
        target = self.target_input.text().strip()
        start_port = self.start_port_input.value()
        end_port = self.end_port_input.value()
        
        # Update UI state
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Status: Scanning...")
        self.status_label.setStyleSheet("font-weight: bold; padding: 8px; background: #fff3e0; border-radius: 5px;")
        self.results_text.clear()
        self.results_text.append(f"🔍 Scanning {target} (ports {start_port}-{end_port})...\n")
        
        # Start scan thread
        self.scan_thread = ScanThread(target, start_port, end_port)
        self.scan_thread.progress.connect(self.on_scan_progress)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.error.connect(self.on_scan_error)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.scan_thread:
            self.scan_thread.stop()
            self.results_text.append("\n⚠️ Scan stopped by user\n")
            self.reset_ui()
    
    def on_scan_progress(self, port: int, is_open: bool):
        """Handle scan progress updates."""
        if port == -1:  # Resolution complete
            return
        
        if is_open:
            self.results_text.append(f"✓ Port {port} is OPEN")
            try:
                service = socket.getservbyport(port, 'tcp')
                self.results_text.append(f"  └─ Service: {service}")
            except:
                pass
    
    def on_scan_finished(self, open_ports: List[int]):
        """Handle scan completion."""
        self.results_text.append(f"\n{'='*50}")
        self.results_text.append(f"✅ Scan completed!")
        self.results_text.append(f"📊 Total open ports found: {len(open_ports)}")
        
        if open_ports:
            self.results_text.append(f"📋 Open ports: {', '.join(map(str, open_ports))}")
        else:
            self.results_text.append("ℹ️ No open ports found in the specified range")
        
        self.reset_ui()
        self.status_label.setText("Status: Completed")
        self.status_label.setStyleSheet("font-weight: bold; padding: 8px; background: #c8e6c9; border-radius: 5px;")
    
    def on_scan_error(self, error_msg: str):
        """Handle scan errors."""
        self.results_text.append(f"\n❌ Error: {error_msg}\n")
        self.reset_ui()
        self.status_label.setText("Status: Error")
        self.status_label.setStyleSheet("font-weight: bold; padding: 8px; background: #ffcdd2; border-radius: 5px;")
    
    def reset_ui(self):
        """Reset UI to idle state."""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status: Idle")
        self.status_label.setStyleSheet("font-weight: bold; padding: 8px; background: #e3f2fd; border-radius: 5px;")
    
    def clear_results(self):
        """Clear the results text area."""
        self.results_text.clear()


def main():
    """Application entry point."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern cross-platform style
    
    # Set application-wide font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = PortScannerGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
