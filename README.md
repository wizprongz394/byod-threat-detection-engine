# BYOD Anomaly Detection System

## 🧠 Overview

This project implements a behavior-based anomaly detection system for Bring Your Own Device (BYOD) environments.
Instead of relying on known attack signatures, the system learns normal network behavior and identifies deviations using machine learning.

The project simulates realistic network activity, captures traffic using Wireshark, extracts behavioral features, and detects anomalies using an Isolation Forest model.

---

## ⚔️ Problem Statement

Traditional security systems rely on known attack signatures, making them ineffective against:

* Unknown threats
* Zero-day attacks
* Insider threats
* BYOD environments with uncontrolled devices

This project addresses the problem by focusing on **behavioral anomaly detection**.

---

## 🏗️ System Architecture

```
BYOD Devices
   ↓
Network Traffic
   ↓
Wireshark Capture
   ↓
PCAP Files
   ↓
Feature Engineering
   ↓
Machine Learning (Isolation Forest)
   ↓
Anomaly Detection
   ↓
(Planned) LLM-based Explanation
   ↓
Response System
```

---

## 🧪 Simulated Scenarios

The system uses controlled behavior simulations to generate realistic network traffic:

* Normal user activity
* Periodic beaconing (C2-like behavior)
* Data exfiltration (high and low volume)
* Endpoint scanning / enumeration
* Burst traffic patterns
* Stealth/randomized behavior

All scenarios are safely simulated using Python scripts and public endpoints.

---

## ⚙️ Tech Stack

* Python
* Wireshark (PCAP capture)
* Pandas / NumPy
* Scikit-learn (Isolation Forest)
* Matplotlib / Seaborn (Visualization)

---

## 🧠 Key Concepts

* Feature Engineering (core focus)
* Behavioral Analysis
* Unsupervised Learning
* Anomaly Detection
* Network Traffic Analysis

---

## 📁 Project Structure

```
byod-anomaly-detection/
│
├── data/
│   ├── raw/              # PCAP files
│   ├── processed/        # Feature datasets
│
├── scenarios/            # Traffic simulation scripts
│
├── src/
│   ├── feature_engineering.py
│   ├── model.py
│   ├── evaluate.py
│
├── notebooks/            # Experiments
├── results/              # Outputs & plots
│
└── main.py
```

---

## 🚀 Goals

* Build a real-world anomaly detection pipeline
* Understand behavior-based security
* Reduce false positives through better features
* Integrate ML + LLM for explainable security (future)

---

## 🧠 Key Insight

> This system does not ask:
> “Is this a known attack?”

> It asks:
> **“Does this behavior look normal?”**

---

## ⚠️ Disclaimer

All attack scenarios are simulated in a controlled environment using safe and ethical methods.
No real systems are exploited.

---

## 👥 Authors

* Your Name
* Partner Name
