import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Load your features file
df = pd.read_csv('.\\train_data_2_grams_labeled.csv')

# Split tf-idf output into separate columns
tfidf_cols = df['tf-idf output'].str.split(',', expand=True)
tfidf_cols = tfidf_cols.astype('float32').fillna(0)

# Optionally, reduce number of features if memory is an issue
# tfidf_cols = tfidf_cols.iloc[:, :1000]

# Other features
other_features = df[['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy']].astype(float).fillna(0)

# Combine all features
X = pd.concat([other_features, tfidf_cols], axis=1)
X.columns = X.columns.map(str)

# Target variable
y = df['label'].astype(int)

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Decision Tree
clf = DecisionTreeClassifier(random_state=42)
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