# -COMP4900E_PQC_QNX_BOOT-

COMP 4900E – Real Time Operating Systems
Carleton University – Winter 2026

Group 4
- Sebastian Ezman
- Renee Hogarth
- Evan Hall
- Roopvir Kang
- Hamza Rizwan

## Project OverView

This project explores the feasibility of integrating Post-Quantum Cryptography (PQC) into a Secure Boot verification framework on the QNX real-time operating system.

## Project Goals

The main goals of this project are:
 1. Implement a Post-Quantum signature verification system using C/C++.
 2. Integrate PQC verification into a secure boot workflow on QNX.
 3. Compare classical vs PQC vs hybrid verification approaches.
 4. Measure system impact including:
     - Boot time
     - Signature verification time
     - Key size
     - Signature size
     - Code size increase
 5. Evaluate whether PQC secure boot is practical for embedded systems.

 ## Repository Structure
 ```
 COMP4900E_PQC_QNX
│
├── docs
│   Project documentation, notes, diagrams, and references
│
├── src
│   Source code for the project
│
│   ├── pqc
│   PQC signature verification implementation
│
│   ├── qcrypto
│   Integration experiments with the QNX qcrypto library
│
│   └── boot
│   Secure boot verification logic and boot-stage simulation
│
├── tests
│   Test files including sample firmware images, signatures, and keys
│
├── results
│   Benchmark outputs, performance measurements, and logs
│
├── README.md
│   Project overview and instructions
│
└── .gitignore
```