import pandas as pd

# Read features CSV (no header)
df1 = pd.read_csv('datasetupdate2_features.csv')
df2 = pd.read_csv('data_tfidf_2_matrix.csv')

# Make sure the file path column has the same name in both files, e.g., 'filename'
df1['filename'] = df1['filename'].str.strip()
df2['filename'] = df2['filename'].str.strip()

# Merge on the file path column
merged = pd.merge(df1, df2, on='filename', how='left')

# Save merged CSV
merged.to_csv('complete_data_features.csv', index=False)