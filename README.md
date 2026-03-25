# Network IDS — Flow Analyser

A desktop application for analysing CICFlowMeter-generated network flow logs
using a trained XGBoost intrusion detection model.

## Requirements
- Windows 10/11
- Anaconda or Miniconda installed
  → https://www.anaconda.com/download

## Setup

### 1. Clone or download this project
Place the folder somewhere on your machine, e.g. `D:\IDS-app`

### 2. Create the conda environment
Open Anaconda Prompt and run:
```
conda env create -f environment.yml
conda activate ids
```

### 3. Run the app
```
conda activate ids
cd D:\IDS-app
python app.py
```

The model file (`xgb_ids_model.pkl`) is included in the `model/` folder.

## Usage
1. Click **UPLOAD CSV LOG**
2. Select a CICFlowMeter-generated `.csv` file
3. Wait for inference to complete
4. View attack charts and flagged flows table

## Input Format
The app expects CSV files exported by **CICFlowMeter** with the standard
78 network flow features. Raw PCAP files are not supported directly —
run them through CICFlowMeter first.

Download CICFlowMeter: https://www.unb.ca/cic/research/applications.html

## Retraining the Model

The training notebook (`notebook.ipynb`) is included if you wish to retrain
or experiment with the model yourself.

### Dataset
This model was trained on the **CIC-IDS-2017** dataset published by the
Canadian Institute for Cybersecurity.

Download it here: https://www.unb.ca/cic/datasets/ids-2017.html

The raw CSV files (~8GB) are **not included** in this repository.
After downloading, place the CSV files in the same directory as the notebook
and run all cells in order.

> **Note:** The dataset is provided by the University of New Brunswick for
> research and educational purposes. By downloading and using it you agree to
> their terms of use. Do not redistribute the raw data files.

## Licensing & Attribution

**Dataset:** CIC-IDS-2017 — Canadian Institute for Cybersecurity, University
of New Brunswick. If you use this project in academic work, please cite the
original dataset paper:
> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani,
> "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
> Characterization", ICISSP 2018.
