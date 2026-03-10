# Capstone Project: Network Intrusion Detection

**Authors:** Abed, Nevin, Heshan

## Overview
This project develops a machine learning-based network intrusion detection system capable of distinguishing between normal network traffic and various cyber attacks in real-time. 

## Data & Methodology
* **Dataset:** KDD Cup 1999 dataset.
* **Preprocessing:** Reduced the original 42 network features down to the 17 most predictive ones to improve computational efficiency.
* **Balancing:** Applied advanced SMOTE techniques to handle severe class imbalances across 26 different attack types.
* **Protocol Analysis:** Analyzed vulnerabilities specific to TCP, UDP, and ICMP protocols.

## Models Evaluated
We trained and evaluated three machine learning models to find the most effective algorithm:
* Random Forest
* XGBoost
* K-Nearest Neighbors (KNN)

## Key Results
* **Random Forest (Recommended):** Achieved 99.5% accuracy and an F1-score of 0.94. It was selected as the optimal model for real-world deployment due to its high interpretability, rapid training speed, and minimal preprocessing requirements.
* **XGBoost:** Achieved a highly competitive 99.7% accuracy but required more careful hyperparameter tuning and longer training times due to its sequential learning nature.
* **KNN:** Trailed with 97.9% accuracy and a much lower F1-score (0.79). It struggled with the high-dimensional feature space, making it unsuitable for real-time detection.

## Tech Stack
* **Language:** R
* **Environment:** RStudio
* **Key Packages:** `ranger`, `xgboost`, `smotefamily`, `caret`, `ggplot2`
