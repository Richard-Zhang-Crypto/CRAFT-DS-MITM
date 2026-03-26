# Improved DS-MITM Attacks on CRAFT via Dynamic Key-Dependent Distinguishers

This repository contains the official source code for the paper: **"Improved DS-MITM Attacks on CRAFT via Dynamic Key-Dependent Distinguishers"**.

This project implements an automated search tool using Mixed-Integer Linear Programming (MILP) to find the optimal Deterministic Truncated Differential (DS) Meet-in-the-Middle (MITM) attacks on the CRAFT block cipher. 

## 📁 Repository Structure

* `craft_ds_mitm.py`: The main Python script containing the MILP model, constraints, and the automated search algorithm.
* `requirements.txt`: The list of Python dependencies required to run the code.
* `LICENSE`: The open-source license for this repository (MIT License).

## 🛠️ Prerequisites & Environment Setup

This code is written in Python 3 and relies heavily on the **Gurobi Optimizer** to solve the MILP models. 

### 1. Install Dependencies
First, clone the repository and install the required Python packages:
```bash
git clone [https://github.com/Richard-Zhang-Crypto/CRAFT-DS-MITM.git](https://github.com/Richard-Zhang-Crypto/CRAFT-DS-MITM.git)
cd CRAFT-DS-MITM
pip install -r requirements.txt
