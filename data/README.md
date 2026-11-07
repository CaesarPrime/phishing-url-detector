# Dataset

The model is trained on the **PhiUSIIL Phishing URL Dataset** (Prasad & Chandra, 2024):
235,795 URLs — 134,850 legitimate and 100,945 phishing.

1. Download it from the UCI Machine Learning Repository:
   https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Unzip it and rename `PhiUSIIL_Phishing_URL_Dataset.csv` to `phishing_dataset.csv`.
3. Place it in this `data/` folder.

Only two columns are used: `URL` and `label`.
In PhiUSIIL, **`label = 0` means phishing** and **`label = 1` means legitimate**.
The training pipeline converts this so that, inside the project, **1 = phishing** and **0 = legitimate**.

The CSV file is large, so it is excluded from Git by `.gitignore`.

Reference: Prasad, A., & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL
detection framework based on similarity index and incremental learning. *Computers & Security, 136*, 103545.
