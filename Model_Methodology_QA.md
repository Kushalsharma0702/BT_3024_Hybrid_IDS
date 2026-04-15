# IDS Model Methodology: Research Q&A

This document answers the methodology questions based on the current implementation in the project code.

## 1) Which algorithms are being used in the model?
The system uses a **hybrid ensemble classifier** with two algorithms:

1. **Random Forest Classifier** (from scikit-learn)
2. **XGBoost Classifier** (from xgboost, configured to use GPU/CUDA)

These two models are combined using a **soft-voting VotingClassifier**, where the final decision is based on weighted class probabilities.

## 2) Are we using a single model or multiple models combined?
We are using **multiple models combined**.

Specifically, this is an **ensemble architecture**:
- Base model 1: Random Forest
- Base model 2: XGBoost
- Meta decision rule: Soft voting with weights `[1, 2]` (higher weight assigned to XGBoost)

So this is not a single standalone classifier; it is a weighted hybrid model.

## 3) Which dataset are we using exactly?
The code uses the **UNSW-NB15** dataset, stored in parquet format, with separate train/test files:

- Training file: `D:\Major_Project\Dataset\UNSW_NB15_training-set.parquet`
- Testing file: `D:\Major_Project\Dataset\UNSW_NB15_testing-set.parquet`

Target label used:
- `label` (binary classification target)

## 4) Are we doing any feature selection or preprocessing?
Yes, both are being done.

### Feature selection
A manual fixed subset of 9 features is used ("Power 9"):
- `dur`
- `sbytes`
- `dbytes`
- `sloss`
- `dloss`
- `sload`
- `dload`
- `ct_src_dport_ltm`
- `ct_dst_sport_ltm`

### Preprocessing
- Data split for internal validation: `train_test_split(..., test_size=0.2, stratify=y, random_state=42)`
- Numerical scaling: `StandardScaler`
  - `fit_transform` on training split
  - `transform` on validation and test splits (correct production practice)

## 5) Does the model output only attack/normal, or also probability/confidence?
It outputs **both**.

- The ensemble first computes class probabilities using `predict_proba(...)`.
- Then a hard decision is made with a confidence threshold:
  - `prediction = 1 (attack)` if probability > 0.90
  - otherwise `0 (normal)`

So the pipeline supports confidence-aware decision making, not just direct hard labels.

## 6) Do we have any mechanism to reduce false positives?
Yes, there are explicit mechanisms in the current design:

1. **High decision threshold (0.90)**
   - Instead of default threshold 0.50, the code uses 0.90 for attack prediction.
   - This is a conservative rule intended to reduce false alarms/false positives.

2. **Class imbalance handling in training**
   - Random Forest uses `class_weight='balanced'`.
   - XGBoost uses `scale_pos_weight=3`.

Primary false-positive control in inference is the **0.90 thresholding strategy**.

## 7) What metrics are we focusing on? Only accuracy or also false positive rate?
The current evaluation is **not limited to accuracy**.

Implemented outputs:
1. **Confusion Matrix**
2. **Classification Report** (precision, recall, F1-score, support per class, plus macro/weighted averages)

Therefore, you can analyze performance beyond accuracy, including behavior related to false positives.

Important note for research reporting:
- **False Positive Rate (FPR)** is not explicitly printed as a standalone metric in the current code.
- However, FPR can be computed from the confusion matrix as:

\[
\text{FPR} = \frac{FP}{FP + TN}
\]

## Suggested Methodology Statement (Paper-ready)
The implemented IDS is a GPU-accelerated hybrid ensemble that combines Random Forest and XGBoost via weighted soft voting. The model is trained and evaluated on UNSW-NB15 (parquet train/test split), using a manually selected nine-feature subset and StandardScaler-based preprocessing. Inference is probability-driven, with a strict 0.90 attack threshold to reduce false positives. Performance assessment uses confusion matrix and classification-report metrics (precision, recall, F1), enabling analysis beyond raw accuracy.
