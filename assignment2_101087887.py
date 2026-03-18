"""
Author: Juela Topi
Assignment: #2
Description: Port Scanner 
"""

# imports
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Python version and OS name
print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# Dictionary storing usual port numbers and the associated service name
common_ports = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}


# NetworkTool parent class
class NetworkTool:

    def __init__(self, target):
        self.__target = target

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value.strip() == "":
            raise ValueError("Target cannot be empty.")
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?
# Using @property and @target.setter allows controlled access to private attributes
# while it keeps the syntax clean. It improves encapsulation by
# validating the values before the assignment and prevents incorrect data from being saved.
# This makes the class more organized and safe.


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, which allows reusing the target
# attribute and its validation logic without having to rewrite the same code.
# By using inheritance, the child class focuses only on scanning behavior,
# while the parent class handles shared functionality.


# PortScanner child class that inherits from NetworkTool
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    # Q4: What would happen without try-except here?
    # Without a try-except block, any socket error such as timeouts or
    # connection failures would cause the program to crash immediately.
    # This will stop the scanning process entirely instead of continuing
    # to check remaining ports. The try-except block ensures stability
    # and allows the scan to continue even if errors occur.

    def scan_port(self, port):
        sock = None   # ✅ FIX (only change)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Socket error on port {port}: {e}")

        finally:
            if sock:   # ✅ FIX (only change)
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously,
    # significantly reducing the total scanning time.
    # If ports were scanned sequentially, the program would take much longer
    # to complete, especially when scanning large ranges.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


# Create save_results function
def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for port, status, service in results:
            cursor.execute("""
            INSERT INTO scans (target, port, status, service, scan_date)
            VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()

        print("Scan results saved successfully.")

    except sqlite3.Error as e:
        print("Database error:", e)


# Create load_past_scans function
def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            print("\n--- Past Scan History ---")
            for row in rows:
                print(f"Target: {row[1]}, Port: {row[2]}, Status: {row[3]}, Service: {row[4]}, Date: {row[5]}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    try:
        target = input("Enter target IP (default 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or end_port > 1024 or start_port > end_port:
            print("Port must be between 1 and 1024 and end port must be >= start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)

    print(f"\nScanning {target} from port {start_port} to {end_port}...\n")

    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    if open_ports:
        print("\n--- Open Ports ---")
        for port, status, service in open_ports:
            print(f"Port {port} ({service}) is {status}")
    else:
        print("No open ports found.")

    print(f"\nTotal Open Ports Found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    view_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()

    if view_history == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a "Port Risk Analyzer" feature that evaluates open ports
# and assigns a security risk level (Low, Medium, High) based on
# the port number and associated service. After scanning,
# the program would generate a summarized security risk report
# to help users understand potential vulnerabilities.