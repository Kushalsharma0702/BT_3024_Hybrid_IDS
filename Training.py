import pandas as pd
import joblib
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix

# --- STEP 1: LOAD & PREP ---
print("--- Initializing GPU Training ---")
train_path = r'D:\Major_Project\Dataset\UNSW_NB15_training-set.parquet'
df = pd.read_parquet(train_path)

# Feature Selection (The 'Power 9' for IDS)
features = ['dur', 'sbytes', 'dbytes', 'sloss', 'dloss', 'sload', 'dload', 'ct_src_dport_ltm', 'ct_dst_sport_ltm']
X = df[features]
y = df['label']

# Split for internal validation
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

# Scaling - WE SAVE THIS TO USE IN TESTING
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)

# --- STEP 2: HYBRID ENSEMBLE ---
# Random Forest (CPU) + XGBoost (GPU)
rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)

# Triggering CUDA for XGBoost
xgb_model = XGBClassifier(
    n_estimators=100, 
    learning_rate=0.05, 
    scale_pos_weight=3, 
    device="cuda",        # Uses your ROG Strix GPU
    tree_method="hist",   # Modern GPU histogram method
    random_state=42
)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb_model)], 
    voting='soft',
    weights=[1, 2]
)

# --- STEP 3: TRAIN & SAVE ---
print("Training the Hybrid Council... (Check nvidia-smi now)")
ensemble.fit(X_train_scaled, y_train)

# SAVE THE ARTIFACTS
joblib.dump(ensemble, 'hybrid_ids_model.pkl')
joblib.dump(scaler, 'ids_scaler.bin')
print("\nSuccess: Model and Scaler saved to D:\Major_Project")

# Quick Internal Check
probs = ensemble.predict_proba(X_val_scaled)[:, 1]
preds = (probs > 0.90).astype(int)
print("\n--- Internal Validation Results (90% Threshold) ---")
print(classification_report(y_val, preds))