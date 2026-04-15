import pandas as pd
import joblib
from pathlib import Path
import sys
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_curve,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / 'hybrid_ids_model.pkl'
SCALER_PATH = BASE_DIR / 'ids_scaler.bin'
TEST_PATH = BASE_DIR / 'Dataset' / 'UNSW_NB15_testing-set.parquet'
PLOT_DIR = BASE_DIR / 'evaluation_plots'
THRESHOLD = 0.90

# --- STEP 1: LOAD THE SAVED BRAIN ---
print("--- Initializing Model Testing ---")
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("Model and Scaler loaded successfully.")
except FileNotFoundError:
    print(f"Error: Could not find model files at {MODEL_PATH} and/or {SCALER_PATH}.")
    print("Run Training.py first, or place model files in the Major_Project folder.")
    sys.exit(1)

# --- STEP 2: LOAD TEST DATASET ---
test_df = pd.read_parquet(TEST_PATH)

# Must use the EXACT same features as training
features = ['dur', 'sbytes', 'dbytes', 'sloss', 'dloss', 'sload', 'dload', 'ct_src_dport_ltm', 'ct_dst_sport_ltm']
X_test = test_df[features]
y_test = test_df['label']

# --- STEP 3: PREPROCESS & PREDICT ---
# Important: Use .transform(), NOT .fit_transform() here
X_test_scaled = scaler.transform(X_test)

print(f"Testing on {len(X_test)} unseen packets...")
probs = model.predict_proba(X_test_scaled)[:, 1]

# 90% Confidence Threshold to eliminate False Alarms
final_preds = (probs > THRESHOLD).astype(int)

# --- STEP 4: FINAL RESULTS ---
print("\n--- FINAL TEST RESULTS ---")
print("Confusion Matrix:")
cm = confusion_matrix(y_test, final_preds)
print(cm)
print("\nClassification Report:")
print(classification_report(y_test, final_preds))


def save_confusion_matrix_heatmap(y_true, y_pred, output_path):
    cm_local = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(7, 5))
    sns.heatmap(cm_local, annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.title('Confusion Matrix Heatmap')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_roc_curve(y_true, y_scores, output_path):
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, label=f'ROC AUC = {roc_auc:.4f}', color='tab:blue')
    plt.plot([0, 1], [0, 1], linestyle='--', color='gray', label='Random')
    plt.title('ROC Curve')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_precision_recall_curve(y_true, y_scores, output_path):
    precision_vals, recall_vals, _ = precision_recall_curve(y_true, y_scores)
    pr_auc = auc(recall_vals, precision_vals)
    plt.figure(figsize=(7, 5))
    plt.plot(recall_vals, precision_vals, color='tab:green', label=f'PR AUC = {pr_auc:.4f}')
    plt.title('Precision-Recall Curve')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.legend(loc='lower left')
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_metric_bar_chart(y_true, y_pred, output_path):
    metrics = {
        'Accuracy': accuracy_score(y_true, y_pred),
        'Precision': precision_score(y_true, y_pred, zero_division=0),
        'Recall': recall_score(y_true, y_pred, zero_division=0),
        'F1 Score': f1_score(y_true, y_pred, zero_division=0),
    }
    names = list(metrics.keys())
    values = list(metrics.values())

    plt.figure(figsize=(8, 5))
    bars = plt.bar(names, values, color=['#4C78A8', '#F58518', '#54A24B', '#E45756'])
    plt.ylim(0, 1)
    plt.title(f'Metrics at Threshold = {THRESHOLD:.2f}')
    plt.ylabel('Score')

    for bar, value in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width() / 2, value + 0.01, f'{value:.3f}', ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_accuracy_vs_threshold(y_true, y_scores, output_path):
    thresholds = np.linspace(0.0, 1.0, 101)
    accuracies = [accuracy_score(y_true, (y_scores >= t).astype(int)) for t in thresholds]
    best_idx = int(np.argmax(accuracies))
    best_threshold = thresholds[best_idx]
    best_accuracy = accuracies[best_idx]

    plt.figure(figsize=(8, 5))
    plt.plot(thresholds, accuracies, color='tab:purple', label='Accuracy')
    plt.scatter([best_threshold], [best_accuracy], color='red', zorder=3, label=f'Best = {best_accuracy:.4f} @ {best_threshold:.2f}')
    plt.axvline(THRESHOLD, linestyle='--', color='gray', label=f'Current threshold = {THRESHOLD:.2f}')
    plt.title('Accuracy vs Threshold')
    plt.xlabel('Threshold')
    plt.ylabel('Accuracy')
    plt.ylim(0, 1)
    plt.legend(loc='best')
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


print("\n--- Generating Evaluation Graphs ---")
PLOT_DIR.mkdir(exist_ok=True)

save_confusion_matrix_heatmap(y_test, final_preds, PLOT_DIR / 'confusion_matrix_heatmap.png')
save_roc_curve(y_test, probs, PLOT_DIR / 'roc_curve.png')
save_precision_recall_curve(y_test, probs, PLOT_DIR / 'precision_recall_curve.png')
save_metric_bar_chart(y_test, final_preds, PLOT_DIR / 'metrics_bar_chart.png')
save_accuracy_vs_threshold(y_test, probs, PLOT_DIR / 'accuracy_vs_threshold.png')

print(f"Saved plots to: {PLOT_DIR}")