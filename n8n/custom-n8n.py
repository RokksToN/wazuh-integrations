#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Enhanced n8n integration for Wazuh with multi-threading and internal rootCA for https
# Credits https://github.com/maikroservice/wazuh-integrations/blob/main/n8n/custom-n8n.py

"""
ossec.conf configuration structure
 <integration>
     <name>custom-n8n</name>
     <hook_url>https://n8n.myserver.com/webhook/XXXXXXXXXXX</hook_url>
	 <level>12</level>
     <alert_format>json</alert_format>
 </integration>
"""

import os
import sys
import json
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional, Dict, Any

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 3
ERR_INVALID_JSON = 4

# Log file
LOG_FILE = "/var/ossec/logs/integrations.log"

# Thread pool configuration
MAX_WORKERS = 100  # Maximum number of concurrent threads
thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Rules to skip (optional)
#SKIP_RULE_IDS = [
#    "87924", "87900", "87901", "87902", "87903", "87904",
#    "86001", "86002", "86003", "87932", "80710", "87929", "87928", "5710",
#]

def log(msg: str):
    """Append debug messages to integration log"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

def read_json(file_path: str):
    """Read and parse JSON file"""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        log(f"ERROR: Alert file not found at {file_path}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        log(f"ERROR: Invalid JSON in alert file: {e}")
        sys.exit(ERR_INVALID_JSON)

def send_to_n8n_thread(payload: dict, hook_url: str):
    """Send the alert payload to n8n webhook in a separate thread"""
    thread_name = threading.current_thread().name
    log(f"Starting n8n webhook call in thread: {thread_name}")
    
    try:
        headers = {"Content-Type": "application/json"}
        res = requests.post(hook_url, json=payload, headers=headers, timeout=10, verify="path/to/your/rootCA.crt")
        log(f"Thread {thread_name}: POST to {hook_url} returned {res.status_code}")
        
        if res.status_code >= 400:
            log(f"Thread {thread_name}: WARNING - Webhook returned error status {res.status_code}")
            
    except requests.exceptions.Timeout:
        log(f"Thread {thread_name}: ERROR - Request timeout for n8n webhook")
    except requests.exceptions.ConnectionError:
        log(f"Thread {thread_name}: ERROR - Connection error for n8n webhook")
    except requests.exceptions.RequestException as e:
        log(f"Thread {thread_name}: ERROR - Request exception: {e}")
    except Exception as e:
        log(f"Thread {thread_name}: ERROR - Unexpected error: {e}")

def send_to_n8n_async(payload: dict, hook_url: str) -> Future:
    """Send the alert payload to n8n webhook asynchronously using thread pool"""
    return thread_pool.submit(send_to_n8n_thread, payload, hook_url)

def build_payload(alert_json: dict) -> Optional[Dict[str, Any]]:
    """Build a detailed message payload"""
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {}).get("name", "agentless")
    rule_id = rule.get("id", "N/A")

    # Skip unwanted rule IDs
    if rule_id in SKIP_RULE_IDS:
        log(f"Skipping rule ID {rule_id}")
        return None

    level = rule.get("level", 0)
    severity = (
        1 if level <= 4 else
        2 if 5 <= level <= 7 else
        3
    )

    payload = {
        "severity": severity,
        "pretext": "Wazuh Alert",
        "title": rule.get("description", "No description"),
        "fields": [
            {"name": "Agent", "value": agent, "inline": True},
            {"name": "Rule ID", "value": rule_id, "inline": True},
            {"name": "Level", "value": str(level), "inline": True},
            {"name": "Location", "value": alert_json.get("location", "N/A"), "inline": False},
        ],
        "timestamp": alert_json.get("timestamp", datetime.utcnow().isoformat()),
        "id": alert_json.get("id", "unknown"),
        "full_log": alert_json.get("full_log", ""),
        "decoder": alert_json.get("decoder", {}).get("name", "N/A"),
        "agent_ip": alert_json.get("agent", {}).get("ip", "N/A"),
        "raw_alert": alert_json,
    }
    return payload

def cleanup_thread_pool():
    """Clean up thread pool resources"""
    log("Shutting down thread pool...")
    thread_pool.shutdown(wait=True)
    log("Thread pool shutdown complete")

def main():
    if len(sys.argv) < 4:
        log("ERROR: Missing required arguments")
        sys.exit(ERR_BAD_ARGUMENTS)

    alert_file = sys.argv[1]
    hook_url = sys.argv[3]

    # Register cleanup function to run at program exit
    import atexit
    atexit.register(cleanup_thread_pool)

    alert_json = read_json(alert_file)
    payload = build_payload(alert_json)
    
    if payload:
        log(f"Submitting alert {payload.get('id', 'unknown')} to thread pool")
        future = send_to_n8n_async(payload, hook_url)
        
        # Optional: You can track the future if needed
        # For now, we just log and continue
        log(f"Alert processing submitted to thread pool. Active threads: {thread_pool._work_queue.qsize()}")
    else:
        log("INFO: Alert skipped (no payload generated)")

if __name__ == "__main__":
    main()
