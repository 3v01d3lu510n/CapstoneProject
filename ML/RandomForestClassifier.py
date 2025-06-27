import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

# Load your features file
df = pd.read_csv('.\\train_data_2_grams_labeled.csv')

# Split tf-idf output into separate columns
tfidf_cols = df['tf-idf output'].str.split(',', expand=True).astype(float)
tfidf_cols.columns = [f'tfidf_{i}' for i in range(tfidf_cols.shape[1])]

# Combine all features (excluding filename and tf-idf output string)
X = pd.concat([
    df[['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy']].astype(float),
    tfidf_cols
], axis=1)

# Target variable
y = df['label'].astype(int)

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Predict and evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Calculate the confusion matrix
cm = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()
print(f'TN: {TN}, FP: {FP}, FN: {FN}, TP: {TP}')

fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
fnr = FN / (FN + TP) if (FN + TP) > 0 else 0

print(f"False Positive Rate (FPR): {fpr:.4f}")
print(f"False Negative Rate (FNR): {fnr:.4f}")