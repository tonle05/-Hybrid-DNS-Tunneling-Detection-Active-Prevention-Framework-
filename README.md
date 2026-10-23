# -Hybrid-DNS-Tunneling-Detection-Active-Prevention-Framework-

A Deep Packet Inspection (DPI)-based system for detecting evasive DNS tunneling using machine learning, behavioral analysis, dynamic risk scoring, and automated IP blocking.

## Features

- DNS traffic analysis using five lexical and protocol-based features.
- Decision Tree classification trained on the CIC-DNS-EXF-2021 dataset.
- Behavioral correlation and dynamic risk assessment.
- Automated IP blocking using Linux `iptables`.
- Real-time security monitoring dashboard built with Streamlit.

## Requirements

- Python 3
- Linux environment with `sudo` and `iptables`
- Suricata configured to generate DNS events in `eve.json`
- `dig` and `ping` for the simulation scripts

Install the required Python packages:

```bash
pip install numpy scikit-learn scapy tldextract streamlit pandas altair
```

## Setup and Usage

### 1. Prepare the Dataset

Place the CIC-DNS-EXF-2021 files in the expected directories:

- `Attacks/`
- `Benign/`

Generate the training dataset:

```bash
python3 build_dataset_cic_from_files.py
```

This generates `cic_unified_features.txt`.

### 2. Train the AI Model

```bash
python3 train_ai_model.py
```

The trained model is saved as `ai_model.pkl`.

### 3. Start the Detection Engine

Ensure Suricata is running and its DNS events are available in `/var/log/suricata/eve.json`.

```bash
sudo -v
sudo python3 GatewayScript.py
```

The engine monitors DNS events, calculates risk scores, and applies temporary firewall rules when critical risk thresholds are reached.

### 4. Launch the Dashboard

Open a second terminal in the project directory:

```bash
streamlit run Streamlit_Dashboard.py
```

Open the local URL displayed by Streamlit in your browser to view security events, risk scores, traffic statistics, and blocked IP addresses.

### 5. Run Evasion Simulations (Optional)

In a separate Linux lab environment, configure the gateway address in the simulation scripts, then run:

```bash
chmod +x evasion_simulation1.sh evasion_simulation2.sh
./evasion_simulation1.sh
./evasion_simulation2.sh
```

The scripts simulate micro-slicing and low-and-slow DNS tunneling patterns.

## Important Notes

- Run active-response and evasion tests only in an isolated, authorized lab environment.
- The gateway uses `192.168.50.1` as its configured gateway IP; update it to match your lab network.
- Start the detection engine and dashboard from the project directory so generated files can be located correctly.
- `calculate_empirical_weights.py` is an optional utility for analyzing DNS record-type distributions.
- The dataset, trained model, Suricata configuration, and required system services must be prepared separately.

