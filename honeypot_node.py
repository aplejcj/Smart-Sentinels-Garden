import os
import sys
import time
import hashlib
import socket
import json
import threading
import random
import shutil
from datetime import datetime, timedelta, timezone
import smtplib, ssl
from email.mime.text import MIMEText
import collections
import pefile
import math
import yara
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- การตั้งค่าและตัวแปร Global ---
HONEYPOT_PATH = "./honeypot_folder"
QUARANTINE_PATH = "./quarantine"
STATE_PATH = "./state"
BLACKLIST_FILE = os.path.join(STATE_PATH, "network_blacklist.json")
VOTES_FILE = os.path.join(STATE_PATH, "pending_votes.json")
CONFIG_FILE = "config.json"
WHITELIST_FILE = "whitelist.json"
YARA_RULES_PATH = "./malware_rules.yar"

yara_rules = None
trusted_hashes = set()
pending_votes = {}
state_lock = threading.Lock()
recent_message_ids = collections.deque(maxlen=1000)

# --- กลไกการเข้ารหัส ---
def encrypt_data(key, data):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key.encode()), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    decryptor = Cipher(algorithms.AES(key.encode()), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- กลไกการจัดการสถานะ (ปลอดภัยต่อ Thread) ---
def load_state():
    global pending_votes
    with state_lock:
        try:
            if not os.path.exists(STATE_PATH): os.makedirs(STATE_PATH)
            with open(VOTES_FILE, 'r') as f:
                saved_votes = json.load(f)
            for k, v in saved_votes.items():
                pending_votes[k] = {'voters': set(v.get('voters', [])), 'timestamp': v.get('timestamp')}
        except (FileNotFoundError, json.JSONDecodeError):
            pending_votes = {}

def save_state():
    with state_lock:
        serializable_votes = {k: {'voters': list(v['voters']), 'timestamp': v['timestamp']} for k, v in pending_votes.items()}
        with open(VOTES_FILE, 'w') as f:
            json.dump(serializable_votes, f, indent=4)

def cleanup_old_votes():
    while True:
        time.sleep(3600)
        with state_lock:
            now = datetime.now(timezone.utc)
            old_hashes = [h for h, v in list(pending_votes.items()) if now - datetime.fromisoformat(v['timestamp'].replace('Z', '+00:00')) > timedelta(hours=24)]
            if old_hashes:
                print(f"[STATE] Cleaning up {len(old_hashes)} expired votes.")
                for h in old_hashes:
                    del pending_votes[h]
                save_state()

# --- กลไกการวิเคราะห์ไฟล์ (ปลอดภัยต่อไฟล์ขนาดใหญ่) ---
def load_yara_rules(path=YARA_RULES_PATH):
    global yara_rules
    try:
        yara_rules = yara.compile(filepath=path)
        print("[INFO] YARA rules loaded successfully.")
    except Exception as e:
        print(f"[ERROR] Could not compile YARA rules: {e}")

def get_file_hash(filepath, chunk_size=8192):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except IOError: return None

def analyze_pe_file(filepath):
    """
    วิเคราะห์ไฟล์ PE โดยใช้ไลบรารี pefile เพื่อค้นหาลักษณะที่น่าสงสัย
    """
    pe_risk = 0
    pe_reasons = []
    
    suspicious_imports = {
        'CreateRemoteThread', 'WriteProcessMemory', 'OpenProcess',
        'VirtualAllocEx', 'GetProcAddress', 'LoadLibraryA'
    }

    try:
        pe = pefile.PE(filepath)
        
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', 'ignore') in suspicious_imports:
                        pe_risk += 5
                        pe_reasons.append(f"Suspicious Import: {imp.name.decode('utf-8', 'ignore')}")
        
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            entropy = section.get_entropy()
            if entropy > 7.0:
                pe_risk += 10
                pe_reasons.append(f"High Entropy Section '{section_name}' ({entropy:.2f})")
                
    except pefile.PEFormatError:
        
        pass
    except Exception as e:
        print(f"[PE_ANALYSIS_ERROR] Could not analyze PE file {filepath}: {e}")
        
    return pe_risk, list(set(pe_reasons)) 

def analyze_file(filepath):
    """
    วิเคราะห์ไฟล์เพื่อหาความเสี่ยง โดยรวมการวิเคราะห์ YARA, Entropy และ PE Structure
    """
    risk_score, reasons = 0, []
    
    try:
        if yara_rules:
            matches = yara_rules.match(filepath=filepath)
            if matches:
                risk_score += 15
                reasons.append(f"YARA Match: {[m.rule for m in matches]}")
        
        byte_counts = [0] * 256
        file_size = 0
        with open(filepath, 'rb') as f:
            
            is_pe_file = f.read(2) == b'MZ'
            f.seek(0) 
            
            while chunk := f.read(8192):
                for byte in chunk:
                    byte_counts[byte] += 1
                file_size += len(chunk)
        
        if file_size > 0:
            entropy = math.fsum(- (count/file_size) * math.log(count/file_size, 2) for count in byte_counts if count > 0)
            if entropy > 7.5:
                risk_score += 10
                reasons.append(f"High Entropy ({entropy:.2f})")
                
        
        if is_pe_file:
            pe_risk, pe_reasons = analyze_pe_file(filepath)
            if pe_risk > 0:
                risk_score += pe_risk
                reasons.extend(pe_reasons)

    except Exception as e:
        print(f"[FILE_ANALYSIS_ERROR] Could not analyze file {filepath}: {e}")
        pass 
        
    return risk_score, reasons

# --- กลไกการจัดการไฟล์และการแจ้งเตือน ---
def quarantine_file(filepath, filename, node_addr):
    if not os.path.exists(QUARANTINE_PATH): os.makedirs(QUARANTINE_PATH)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    q_filename = f"{timestamp}_{node_addr.replace(':', '_')}_{filename}"
    dest_path = os.path.join(QUARANTINE_PATH, q_filename)
    try:
        shutil.move(filepath, dest_path)
        return True
    except Exception: return False

def send_email_alert(filename, risk_score, reasons, config):
    settings = config.get('email_settings', {})
    sender, password, receiver = settings.get('sender_email'), settings.get('sender_password'), settings.get('receiver_email')
    if not all([sender, password, receiver]): return
    subject = f"[IronForest Node Alert] High-Risk File Detected: {filename}"
    body = f"A high-risk file has been detected and blocked by an IronForest node.\n\n- Filename: {filename}\n- Risk Score: {risk_score} (Threshold: {config['risk_threshold']})\n- Reasons: {', '.join(reasons) if reasons else 'N/A'}\n\nThis threat has been quarantined locally and broadcasted."
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'], msg['From'], msg['To'] = subject, sender, receiver
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
        print(f"[EMAIL] Alert for '{filename}' sent successfully.")
    except Exception as e: print(f"[EMAIL ERROR] Could not send email: {e}")

# --- กลไกเครือข่าย (เข้ารหัสและซิงค์ข้อมูล) ---
def log_to_observer(log_msg, config):
    try:
        host, port_str = config['observer_addr'].split(':')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, int(port_str)))
            s.sendall(log_msg.encode('utf-8'))
    except Exception: pass

def send_message(host, port, message, config):
    message['msg_id'] = hashlib.sha256(os.urandom(32)).hexdigest()
    message['timestamp'] = datetime.now(timezone.utc).isoformat()
    try:
        key = config['encryption_key']
        encrypted_message = encrypt_data(key, json.dumps(message).encode('utf-8'))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(encrypted_message)
    except Exception: pass

def update_network_blacklist(file_hash, node_addr, config):
    with state_lock:
        try:
            with open(BLACKLIST_FILE, 'r') as f: blacklist = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): blacklist = {}
        if file_hash not in blacklist:
            blacklist[file_hash] = datetime.now().isoformat()
            with open(BLACKLIST_FILE, 'w') as f: json.dump(blacklist, f, indent=4)
            log_msg = f"[{node_addr}] NETWORK BLACKLISTED: Hash {file_hash[:10]}... reached quorum."
            print(log_msg)
            log_to_observer(log_msg, config)

def threat_listener(node_port, node_addr, config):
    key = config['encryption_key']
    host = "127.0.0.1"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, node_port))
        s.listen()
        log_to_observer(f"[{node_addr}] Listener started.", config)
        while True:
            conn, _ = s.accept()
            with conn:
                try:
                    data = conn.recv(4096)
                    if not data: continue
                    
                    decrypted_data = decrypt_data(key, data)
                    message = json.loads(decrypted_data.decode('utf-8'))
                    
                    msg_id = message.get('msg_id')
                    msg_time = datetime.fromisoformat(message.get('timestamp').replace('Z', '+00:00'))
                    if msg_id in recent_message_ids or (datetime.now(timezone.utc) - msg_time) > timedelta(seconds=config['message_ttl_sec']):
                        continue
                    recent_message_ids.append(msg_id)

                    msg_type = message.get('type')
                    source_node = message.get('source_node')

                    if msg_type == 'vote':
                        file_hash = message.get('hash')
                        log_msg = f"[{node_addr}] <- Received vote for hash {file_hash[:10]} from {source_node}"
                        print(log_msg)
                        log_to_observer(log_msg, config)
                        with state_lock:
                            pending_votes.setdefault(file_hash, {'voters': set(), 'timestamp': datetime.now(timezone.utc).isoformat()})['voters'].add(source_node)
                            save_state()
                            if len(pending_votes[file_hash]['voters']) >= config['vote_threshold']:
                                update_network_blacklist(file_hash, node_addr, config)
                    
                    elif msg_type == 'sync_request':
                        try:
                            with open(BLACKLIST_FILE, 'r') as f: my_blacklist = json.load(f)
                        except (FileNotFoundError, json.JSONDecodeError): my_blacklist = {}
                        response_msg = {'type': 'sync_response', 'blacklist': my_blacklist, 'source_node': node_addr}
                        r_host, r_port = source_node.split(':')
                        send_message(r_host, int(r_port), response_msg, config)

                    elif msg_type == 'sync_response':
                        their_blacklist = message.get('blacklist', {})
                        for h, ts in their_blacklist.items():
                            update_network_blacklist(h, node_addr, config)
                            
                except Exception: pass

def yara_updater(config):
    while True:
        try:
            print("[YARA] Checking for rule updates...")
            response = requests.get(config['yara_rules_url'], timeout=10)
            if response.status_code == 200:
                with open(YARA_RULES_PATH, 'wb') as f: f.write(response.content)
                load_yara_rules()
        except Exception as e: print(f"[YARA] Update failed: {e}")
        time.sleep(config['yara_update_interval_sec'])

def periodic_sync(peers, node_addr, config):
    while True:
        time.sleep(config['state_check_interval_sec'])
        print("[SYNC] Performing periodic state check...")
        message = {"type": "sync_request", "source_node": node_addr}
        gossip_threat(message, peers, len(peers), node_addr, config) # Send sync request to all peers

def gossip_threat(threat_data, peers, gossip_count, node_addr, config):
    selected_peers = random.sample(peers, min(len(peers), gossip_count))
    log_to_observer(f"[{node_addr}] Gossiping threat to {selected_peers}", config)
    for peer in selected_peers:
        try:
            host, port_str = peer.split(':')
            send_message(host, int(port_str), threat_data, config)
        except Exception: pass

# --- การทำงานหลัก ---
def main():
    try:
        config = load_config()
        global trusted_hashes
        with open(WHITELIST_FILE, 'r') as f: trusted_hashes = set(json.load(f).get('hashes',[]))
    except FileNotFoundError as e:
        print(f"[FATAL] Critical file missing: {e}. Exiting.")
        sys.exit(1)
        
    load_yara_rules(YARA_RULES_PATH)
    load_state()
    
    node_port = int(sys.argv[1])
    node_addr = f"127.0.0.1:{node_port}"
    peers = [p for p in config['peer_nodes'] if p != node_addr]

    # เริ่ม Threads การทำงานเบื้องหลัง
    threading.Thread(target=threat_listener, args=(node_port, node_addr, config), daemon=True).start()
    threading.Thread(target=yara_updater, args=(config,), daemon=True).start()
    threading.Thread(target=cleanup_old_votes, daemon=True).start()
    threading.Thread(target=periodic_sync, args=(peers, node_addr, config), daemon=True).start()
    
    time.sleep(1)
    initial_sync(peers, node_addr, config)

    log_to_observer(f"[{node_addr}] Node started.", config)
    known_files = set()
    
    while True:
        try:
            current_files = set(os.listdir(HONEYPOT_PATH))
            new_files = current_files - known_files
            if new_files:
                for filename in new_files:
                    filepath = os.path.join(HONEYPOT_PATH, filename)
                    if not os.path.isfile(filepath): continue
                    
                    file_hash = get_file_hash(filepath)
                    
                    try:
                        with open(BLACKLIST_FILE, 'r') as f: network_blacklist = json.load(f)
                    except (FileNotFoundError, json.JSONDecodeError): network_blacklist = {}
                    
                    if not file_hash or file_hash in trusted_hashes or file_hash in network_blacklist:
                        known_files.add(filename)
                        continue
                    
                    risk_score, reasons = analyze_file(filepath)
                    if risk_score >= config['risk_threshold']:
                        log_msg = f"[{node_addr}] DETECTED: {filename} (Score: {risk_score})"
                        print(log_msg)
                        log_to_observer(log_msg, config)
                        
                        if quarantine_file(filepath, filename, node_addr):
                            with state_lock:
                                threat_data = {"type": "vote", "hash": file_hash, "source_node": node_addr}
                                pending_votes.setdefault(file_hash, {'voters': set(), 'timestamp': datetime.now(timezone.utc).isoformat()})['voters'].add(node_addr)
                                save_state()
                                gossip_threat(threat_data, peers, config['gossip_count'], node_addr, config)
                                if len(pending_votes[file_hash]['voters']) >= config['vote_threshold']:
                                    update_network_blacklist(file_hash, node_addr, config)
                            send_email_alert(filename, risk_score, reasons, config)
                        continue
                
                known_files.update(new_files)
            time.sleep(2)
        except KeyboardInterrupt:
            log_to_observer(f"[{node_addr}] Node stopped.", config)
            break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python honeypot_node.py <port_for_this_node>")
    else:
        main()
