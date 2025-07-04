🌳 IronForest: Decentralized Cyber Immunity Network 🛡️
A next-generation, peer-to-peer cybersecurity system designed to proactively detect, analyze, and neutralize file-based threats. Inspired by the resilience of a forest ecosystem, each node in the network acts as an intelligent, autonomous sentinel, working together to create a self-healing and robust defensive network.

⭐ Key Features
🛡️ Decentralized & Resilient: No single point of failure. The network remains fully operational even if some nodes go offline.

🔬 Advanced Static Analysis: Utilizes YARA rules, Entropy analysis, and other techniques to perform deep-file analysis and detect sophisticated threats.

🤝 Quorum Consensus: Prevents the spread of false positives and Sybil attacks by requiring verification from multiple peers before a threat is blacklisted network-wide.

🤫 Gossip Protocol: Efficiently disseminates threat intelligence across the network without creating a bottleneck, ensuring rapid response times.

🔭 Centralized Observer Node: A dedicated observer provides a unified, real-time view of all network activity for administrators, without compromising the decentralized nature of the defense system.

🔄 Automatic YARA Rule Updates: Nodes automatically fetch the latest threat definitions from a central, user-defined URL, keeping the system's "brain" up-to-date.

🔒 Immediate Quarantine: Suspicious files are instantly moved to a secure quarantine folder upon detection, neutralizing the threat before it can execute.

🏗️ System Architecture
The system consists of two primary components and several configuration files:

honeypot_node.py (The Sentinel Tree): This is the core of the system. Each running instance acts as an independent node in the forest. It monitors a honeypot folder, analyzes new files, communicates with peers, and quarantines threats.

observer.py (The Watchtower): A simple, standalone server that listens for log messages from all nodes, providing a centralized, human-readable overview of all network events.

config.json: The master configuration file for the entire network.

whitelist.json: A list of trusted file hashes that should never be quarantined.

malware_rules.yar: The knowledge base for the YARA analysis engine.

🚀 Getting Started
Follow these steps to set up and run your own IronForest network.

1. Prerequisites
Python 3.8+

Git

2. Installation
First, clone the repository to your local machine:

Bash

git clone https://github.com/YOUR_USERNAME/IronForest.git
cd IronForest
It is highly recommended to use a virtual environment:

Bash

python -m venv venv
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate
Install all the necessary libraries from requirements.txt:

Bash

pip install -r requirements.txt
3. Configuration ⚙️
Before running the system, you must configure the config.json file:

JSON

{
    "email_settings": {
        "sender_email": "your_email@gmail.com",
        "sender_password": "your_app_password_here",
        "receiver_email": "admin_email@example.com"
    },
    "yara_rules_url": "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/malware_rules.yar",
    "observer_addr": "127.0.0.1:10000",
    "peer_nodes": [
        "127.0.0.1:9997",
        "127.0.0.1:9998",
        "127.0.0.1:9999"
    ],
    "gossip_count": 2,
    "vote_threshold": 2,
    "risk_threshold": 20,
    "yara_update_interval_sec": 21600
}
email_settings: Configure your Gmail credentials for alerts. Remember to use a Google App Password.

yara_rules_url: Provide a raw link to your malware_rules.yar file (e.g., from a GitHub repository).

peer_nodes: List the addresses and ports of all nodes that will participate in the network.

▶️ How to Run
You will need to open multiple terminal windows to simulate the network.

Terminal 1: Start the Observer Node
This window will show you all logs from the entire network.

Bash

python observer.py
Terminal 2: Start Node 1
Each node needs to be assigned a unique port from your config.json.

Bash

python honeypot_node.py 9997
Terminal 3: Start Node 2

Bash

python honeypot_node.py 9998
Terminal 4: Start Node 3

Bash

python honeypot_node.py 9999
🔬 Demonstration
Drop a malicious file (e.g., from your test_malware folder) into the honeypot_folder.

Observe the Terminals:

One of the honeypot_node.py terminals will detect the file, analyze it, and immediately move it to the quarantine folder.

It will then "gossip" the threat information to its peers.

Watch the Quorum:

To simulate consensus, drop the same file again (or have another node detect it).

Once the number of nodes confirming the threat reaches the vote_threshold, you will see a NETWORK BLACKLISTED message in the Observer Node's terminal.

Check the Observer:

The observer.py terminal provides a clean, timestamped log of all these events, giving you a complete overview of the network's defensive actions.