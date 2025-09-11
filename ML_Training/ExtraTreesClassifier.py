import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
from sklearn.model_selection import learning_curve
from scipy import sparse

# Load your features file
df = pd.read_csv('.\\complete_data_features_labeled.csv')

# Split tf-idf output into separate columns and convert to sparse matrix
tfidf_cols = df['tf-idf output'].str.split(',', expand=True).astype(np.float32)
tfidf_cols_sparse = sparse.csr_matrix(tfidf_cols)

# Combine all features
other_features = df[['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy']].astype(np.float32)
characteristics = df['characteristics_flag'].astype(int).values.reshape(-1, 1)
X = sparse.hstack([
    other_features,
    characteristics,
    tfidf_cols_sparse
]).tocsr()  # Convert to CSR format for efficiency

# Target variable
y = df['label'].astype(int)

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train ExtraTreesClassifier
clf = ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Predict and evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()
print(f'TN: {TN}, FP: {FP}, FN: {FN}, TP: {TP}')

fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
fnr = FN / (FN + TP) if (FN + TP) > 0 else 0

print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"False Negative Rate (FNR): {fnr:.4f}")

# # 1. Compare Training vs Testing Scores
# train_score = clf.score(X_train, y_train)
# test_score = clf.score(X_test, y_test)

# print("\nOverfitting Detection Metrics:")
# print(f"Training Score: {train_score:.4f}")
# print(f"Testing Score: {test_score:.4f}")
# print(f"Score Difference: {train_score - test_score:.4f}")

# # 2. Cross-validation scores
# cv_scores = cross_val_score(clf, X, y, cv=5)
# print(f"\nCross-validation scores: {cv_scores}")
# print(f"CV Mean: {cv_scores.mean():.4f}")
# print(f"CV Std: {cv_scores.std():.4f}")

# # 3. Feature Importance Analysis
# feature_importance = pd.DataFrame({
#     'feature': X.columns,
#     'importance': clf.feature_importances_
# })
# feature_importance = feature_importance.sort_values('importance', ascending=False)

# # Plot feature importance
# plt.figure(figsize=(10, 6))
# plt.bar(range(len(feature_importance['importance'])), feature_importance['importance'])
# plt.xticks(range(len(feature_importance['importance'])), feature_importance['feature'], rotation=90)
# plt.title('Feature Importance')
# plt.tight_layout()
# plt.savefig('feature_importance.png')
# plt.close()

# 4. Learning Curves

# train_sizes, train_scores, test_scores = learning_curve(
#     clf, X, y, cv=5, n_jobs=-1, 
#     train_sizes=np.linspace(0.1, 1.0, 10)
# )

# train_mean = np.mean(train_scores, axis=1)
# train_std = np.std(train_scores, axis=1)
# test_mean = np.mean(test_scores, axis=1)
# test_std = np.std(test_scores, axis=1)

# plt.figure(figsize=(10, 6))
# plt.plot(train_sizes, train_mean, label='Training score')
# plt.plot(train_sizes, test_mean, label='Cross-validation score')
# plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1)
# plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.1)
# plt.xlabel('Training Examples')
# plt.ylabel('Score')
# plt.title('Learning Curves')
# plt.legend(loc='best')
# plt.grid(True)
# plt.savefig('learning_curves.png')
# plt.close()

# Get probability scores for ROC curve
y_scores = clf.predict_proba(X_test)[:, 1]

# Calculate ROC curve and AUC
fpr, tpr, thresholds = roc_curve(y_test, y_scores)
roc_auc = auc(fpr, tpr)

# Plot ROC curve
plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, 
         label=f'ROC curve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc="lower right")
plt.grid(True)
plt.savefig('roc_curve.png')
plt.close()

# Print AUC score
print(f"\nAUC-ROC Score: {roc_auc:.4f}")

# joblib.dump(clf, 'extra_trees_classifier.pkl')