import sys
import threading
import socket
import time
from pythonping import ping
from getmac import get_mac_address
from rich.console import Console
from rich.table import Table
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton,
                             QTableWidget, QTableWidgetItem, QToolBar, QAction, QStatusBar)
from PyQt5.QtCore import Qt

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Timeout for the socket operation
    try:
        result = sock.connect_ex((ip, int(port)))
        if result == 0:
            return f"{port}"
        else:
            return f""
    finally:
        sock.close()

def ping_ip(ip, ports, results, lock, current_ip, done):
    try:
        response = ping(ip, count=1, timeout=1)
        hostname = socket.getfqdn(ip)
        mac_address = get_mac_address(ip=ip)
        port_status = [check_port(ip, port) for port in ports.split(',') if port.strip().isdigit()]

        if response.success():
            with lock:
                results.append((ip, "Up", hostname, mac_address, " ".join(port_status)))

        with lock:
            current_ip[0] = ip
            done[0] += 1  # Increment the count of completed pings
    except Exception as e:
        with lock:
            results.append((ip, "Error", str(e), "N/A", "N/A"))
            current_ip[0] = ip
            done[0] += 1

def scan_network(subnet, ports):
    console = Console()
    threads = []
    results = []
    current_ip = [""]
    done = [0]
    total_ips = 255
    lock = threading.Lock()

    with console.status("") as status:
        for i in range(1, 256):  # Assuming a /24 subnet
            ip = f"{subnet}.{i}"
            thread = threading.Thread(target=ping_ip, args=(ip, ports, results, lock, current_ip, done))
            threads.append(thread)
            thread.start()

        while done[0] < total_ips:
            with lock:
                status.update(f"[bold green]Scanning IP: {current_ip[0]} - Completed {done[0]}/{total_ips}")
            time.sleep(0.1)

        for thread in threads:
            thread.join()

    table = Table()
    table.add_column("IP Address", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Hostname", style="yellow")
    table.add_column("MAC Address", style="green")
    table.add_column("Open Ports", style="blue")

    for ip, status, hostname, mac, ports in sorted(results, key=lambda x: x[0]):
        table.add_row(ip, status, hostname, mac, ports)

    console.print(table)


def guiscan(subnet, ports, table, status_bar):
    console = Console()
    threads = []
    results = []
    current_ip = [""]
    done = [0]
    total_ips = 255
    lock = threading.Lock()

    def update_table():
        with lock:
            table.setRowCount(len(results))
            for row, (ip, status, hostname, mac, ports) in enumerate(sorted(results, key=lambda x: x[0])):
                table.setItem(row, 0, QTableWidgetItem(ip))
                table.setItem(row, 1, QTableWidgetItem(status))
                table.setItem(row, 2, QTableWidgetItem(hostname))
                table.setItem(row, 3, QTableWidgetItem(mac))
                table.setItem(row, 4, QTableWidgetItem(ports))
        QApplication.processEvents()  # Keep GUI responsive

    def periodic_update():
        update_table()
        if done[0] < total_ips:
            QTimer.singleShot(100, periodic_update)  # Schedule the next update
        else:
            status_bar.showMessage("Scan Complete")

    with console.status("") as status:
        for i in range(1, 256):  # Assuming a /24 subnet
            ip = f"{subnet}.{i}"
            thread = threading.Thread(target=ping_ip, args=(ip, ports, results, lock, current_ip, done))
            threads.append(thread)
            thread.start()

        QTimer.singleShot(100, periodic_update)  # Start periodic updates

    console.print("Scan Complete")


def run_gui():
    app = QApplication(sys.argv)
    window = QMainWindow()
    window.setWindowTitle("Advanced IP Scanner")
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    layout = QVBoxLayout()

    table = QTableWidget()
    table.setColumnCount(5)
    table.setHorizontalHeaderLabels(["IP Address", "Status", "Hostname", "MAC Address", "Open Ports"])
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)

    status_bar = QStatusBar()
    window.setStatusBar(status_bar)

    lbl_subnet = QLabel("Enter the subnet (e.g., 192.168.1):")
    txt_subnet = QLineEdit()
    lbl_ports = QLabel("Enter the ports (e.g., 22,80,443 | 10-80 | 8080):")
    txt_ports = QLineEdit()
    btn_scan = QPushButton("Scan Network")

    btn_scan.clicked.connect(lambda: guiscan(txt_subnet.text(), txt_ports.text(), table, status_bar))

    layout.addWidget(lbl_subnet)
    layout.addWidget(txt_subnet)
    layout.addWidget(lbl_ports)
    layout.addWidget(txt_ports)
    layout.addWidget(btn_scan)
    layout.addWidget(table)

    central_widget.setLayout(layout)
    window.resize(520, 460)
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    if len(sys.argv) == 3:
        subnet = sys.argv[1]
        ports = sys.argv[2]
        scan_network(subnet, ports)
    else:
        run_gui()
