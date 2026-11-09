# Reducing the Memory Complexity of DS-MITM Attacks on CRAFT

This repository contains the source code accompanying the paper **“Reducing the Memory Complexity of DS-MITM Attacks on CRAFT.”**

The paper introduces the Dynamic Key-Dependent Distinguisher (DKDD) technique to reduce the memory requirements of Demirci–Selçuk meet-in-the-middle (DS-MITM) attacks. The technique uses key information shared between the distinguisher and the key-recovery phase to construct smaller sequence tables.

This repository provides an automated search tool based on Mixed-Integer Linear Programming (MILP) for identifying DS-MITM attack configurations on CRAFT. The tool supports the attack constructions presented in the paper.

## Repository Structure

- `craft_ds_mitm.py` — Main Python script containing the MILP model, constraints, and search procedure.
- `requirements.txt` — Python dependencies.
- `LICENSE` — MIT License.

## Requirements and Setup

The tool requires Python 3 and the Gurobi Optimizer. A valid Gurobi license is required to solve models that exceed the limits of its restricted license.

### Install Dependencies

Clone the repository and install the required Python packages:

```bash
git clone https://github.com/Richard-Zhang-Crypto/CRAFT-DS-MITM.git
cd CRAFT-DS-MITM
pip install -r requirements.txt
```
