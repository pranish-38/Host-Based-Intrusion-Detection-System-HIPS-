#!/usr/bin/env python3
"""
Host-based Intrusion Prevention System (HIPS)
Main Engine - Monitors system activity and responds to threats
"""

import os
import sys
import time
import json
import psutil
import signal
import hashlib
import logging
from datetime import datetime
from threading import Thread
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class HIPSConfig:
    """Configuration manager for HIPS"""
    def __init__(self, config_file='hips_config.json'):
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.monitored_paths = config.get('monitored_paths', ['/etc', '/bin', '/usr/bin'])
                self.suspicious_processes = config.get('suspicious_processes', [])
                self.blocked_ports = config.get('blocked_ports', [])
                self.whitelist_ips = config.get('whitelist_ips', ['127.0.0.1'])
                self.max_cpu_percent = config.get('max_cpu_percent', 90)
                self.max_memory_percent = config.get('max_memory_percent', 80)
                self.alert_mode = config.get('alert_mode', 'log')  # log, block, terminate
        except FileNotFoundError:
            self.create_default_config()
            self.load_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        default_config = {
            "monitored_paths": ["/etc/passwd", "/etc/shadow", "/root", "/home"],
            "suspicious_processes": ["nc", "ncat", "netcat", "reverse_shell", "mimikatz"],
            "blocked_ports": [4444, 5555, 6666, 31337],
            "whitelist_ips": ["127.0.0.1", "::1"],
            "max_cpu_percent": 90,
            "max_memory_percent": 80,
            "alert_mode": "log"
        }
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"[+] Created default config: {self.config_file}")


class FileMonitor(FileSystemEventHandler):
    """Monitor file system for suspicious changes"""
    def __init__(self, hips_logger):
        self.logger = hips_logger
        self.file_hashes = {}
        
    def on_modified(self, event):
        if not event.is_directory:
            self.check_file_integrity(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.logger.log_alert('FILE_CREATED', f"New file created: {event.src_path}")
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.logger.log_alert('FILE_DELETED', f"File deleted: {event.src_path}")
    
    def check_file_integrity(self, filepath):
        """Check if file has been modified"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            if filepath in self.file_hashes:
                if self.file_hashes[filepath] != file_hash:
                    self.logger.log_alert('FILE_MODIFIED', 
                        f"Critical file modified: {filepath}")
            else:
                self.file_hashes[filepath] = file_hash
        except Exception as e:
            pass


class ProcessMonitor:
    """Monitor running processes for suspicious activity"""
    def __init__(self, config, hips_logger):
        self.config = config
        self.logger = hips_logger
        self.known_processes = set()
        self.running = False
    
    def start(self):
        """Start process monitoring thread"""
        self.running = True
        thread = Thread(target=self._monitor_loop, daemon=True)
        thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.check_processes()
                time.sleep(2)
            except Exception as e:
                self.logger.log_error(f"Process monitor error: {e}")
    
    def check_processes(self):
        """Check all running processes"""
        current_processes = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                current_processes.add(pid)
                
                # Check for new processes
                if pid not in self.known_processes:
                    self.logger.log_event('NEW_PROCESS', 
                        f"New process detected: {name} (PID: {pid})")
                    self.known_processes.add(pid)
                
                # Check for suspicious process names
                if any(susp in name.lower() for susp in self.config.suspicious_processes):
                    self.logger.log_alert('SUSPICIOUS_PROCESS', 
                        f"Suspicious process: {name} (PID: {pid})")
                    if self.config.alert_mode == 'terminate':
                        self.terminate_process(pid, name)
                
                # Check for resource abuse
                if info['cpu_percent'] > self.config.max_cpu_percent:
                    self.logger.log_alert('HIGH_CPU', 
                        f"High CPU usage: {name} (PID: {pid}) - {info['cpu_percent']}%")
                
                if info['memory_percent'] > self.config.max_memory_percent:
                    self.logger.log_alert('HIGH_MEMORY', 
                        f"High memory usage: {name} (PID: {pid}) - {info['memory_percent']}%")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Detect terminated processes
        terminated = self.known_processes - current_processes
        self.known_processes = current_processes
    
    def terminate_process(self, pid, name):
        """Terminate a malicious process"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.logger.log_alert('PROCESS_TERMINATED', 
                f"Terminated malicious process: {name} (PID: {pid})")
        except Exception as e:
            self.logger.log_error(f"Failed to terminate process {pid}: {e}")


class NetworkMonitor:
    """Monitor network connections"""
    def __init__(self, config, hips_logger):
        self.config = config
        self.logger = hips_logger
        self.running = False
    
    def start(self):
        """Start network monitoring thread"""
        self.running = True
        thread = Thread(target=self._monitor_loop, daemon=True)
        thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.check_connections()
                time.sleep(0.1)
            except Exception as e:
                self.logger.log_error(f"Network monitor error: {e}")
    
    def check_connections(self):
        """Check active network connections"""
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            try:
                if conn.status == 'ESTABLISHED':
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    
                    if conn.raddr:
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                        
                        # Check for suspicious ports
                        if conn.raddr.port in self.config.blocked_ports:
                            self.logger.log_alert('SUSPICIOUS_PORT', 
                                f"Connection to blocked port: {remote_addr}")
                        
                        # Check for non-whitelisted external connections
                        if conn.raddr.ip not in self.config.whitelist_ips:
                            # Log external connections
                            if conn.pid:
                                try:
                                    proc = psutil.Process(conn.pid)
                                    proc_name = proc.name()
                                    self.logger.log_event('EXTERNAL_CONNECTION', 
                                        f"External connection: {proc_name} -> {remote_addr}")
                                except:
                                    pass
            except Exception:
                continue


class HIPSLogger:
    """Logging system for HIPS"""
    def __init__(self, log_file='hips.log'):
        self.log_file = log_file
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('HIPS')
    
    def log_event(self, event_type, message):
        """Log normal events"""
        self.logger.info(f"[{event_type}] {message}")
        print(f"[INFO] [{event_type}] {message}")
    
    def log_alert(self, alert_type, message):
        """Log security alerts"""
        self.logger.warning(f"[ALERT] [{alert_type}] {message}")
        print(f"\033[93m[ALERT] [{alert_type}] {message}\033[0m")  # Yellow
    
    def log_error(self, message):
        """Log errors"""
        self.logger.error(message)
        print(f"\033[91m[ERROR] {message}\033[0m")  # Red


class HIPS:
    """Main HIPS Engine"""
    def __init__(self):
        print("""
╔═══════════════════════════════════════════════════════╗
║   Host-based Intrusion Prevention System (HIPS)      ║
║                  Security Monitor                     ║
╚═══════════════════════════════════════════════════════╝
        """)
        
        self.config = HIPSConfig()
        self.logger = HIPSLogger()
        self.file_monitor = FileMonitor(self.logger)
        self.process_monitor = ProcessMonitor(self.config, self.logger)
        self.network_monitor = NetworkMonitor(self.config, self.logger)
        self.observers = []
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def start(self):
        """Start all monitoring components"""
        self.logger.log_event('SYSTEM_START', 'HIPS Starting...')
        
        # Check for root privileges
        if os.geteuid() != 0:
            print("\033[91m[!] Warning: HIPS requires root privileges for full functionality\033[0m")
        
        # Start file monitoring
        for path in self.config.monitored_paths:
            if os.path.exists(path):
                observer = Observer()
                observer.schedule(self.file_monitor, path, recursive=True)
                observer.start()
                self.observers.append(observer)
                self.logger.log_event('FILE_MONITOR', f"Monitoring: {path}")
        
        # Start process monitoring
        self.process_monitor.start()
        self.logger.log_event('PROCESS_MONITOR', 'Process monitoring started')
        
        # Start network monitoring
        self.network_monitor.start()
        self.logger.log_event('NETWORK_MONITOR', 'Network monitoring started')
        
        self.running = True
        self.logger.log_event('SYSTEM_READY', 'HIPS is now active and monitoring')
        
        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop all monitoring components"""
        print("\n[*] Shutting down HIPS...")
        self.running = False
        
        # Stop file observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        # Stop monitors
        self.process_monitor.stop()
        self.network_monitor.stop()
        
        self.logger.log_event('SYSTEM_STOP', 'HIPS stopped')
        print("[+] HIPS stopped successfully")
        sys.exit(0)
    
    def signal_handler(self, sig, frame):
        """Handle shutdown signals"""
        self.stop()


if __name__ == '__main__':
    try:
        hips = HIPS()
        hips.start()
    except Exception as e:
        print(f"\033[91m[ERROR] Fatal error: {e}\033[0m")
        sys.exit(1)
