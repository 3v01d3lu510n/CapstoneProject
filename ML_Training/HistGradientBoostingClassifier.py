import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from scipy import sparse
from sklearn.inspection import permutation_importance

import joblib

# Load your features file
df = pd.read_csv('.\\complete_data_features_labeled.csv')

# Split tf-idf output into separate columns
tfidf_cols = df['tf-idf output'].str.split(',', expand=True)
tfidf_cols = tfidf_cols.astype('float32')

# Convert tfidf_cols to a sparse matrix
tfidf_sparse = sparse.csr_matrix(tfidf_cols.values)

# Other features as dense
other_features = df[['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy', 'characteristics_flag']].astype(float).values
other_features_sparse = sparse.csr_matrix(other_features)

# Combine dense and sparse features
X_sparse = sparse.hstack([other_features_sparse, tfidf_sparse])

# Target variable
y = df['label'].astype(int).values

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X_sparse, y, test_size=0.2, random_state=42)

# GradientBoostingClassifier does NOT support sparse input directly.
# So, convert to dense (may require a lot of memory for large data)
X_train_dense = X_train.toarray()
X_test_dense = X_test.toarray()

# Train Gradient Boosting
clf = HistGradientBoostingClassifier(random_state=42)
clf.fit(X_train_dense, y_train)

# Predict and evaluate
y_pred = clf.predict(X_test_dense)
print(classification_report(y_test, y_pred))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()
print(f'TN: {TN}, FP: {FP}, FN: {FN}, TP: {TP}')

fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
fnr = FN / (FN + TP) if (FN + TP) > 0 else 0

print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"False Negative Rate (FNR): {fnr:.4f}")



