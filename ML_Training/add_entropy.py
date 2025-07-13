import pandas as pd
import os

# Load the files
char_df = pd.read_csv('datasetupdate2_flag.csv')
entropy_df = pd.read_csv('.\\data_dump\\datasetupdate2_entropy.csv')

# Extract filename from FilePath in entropy_df
entropy_df['filename'] = entropy_df['FilePath']
# If your characteristics file has a 'filename' column, use it directly.
# If not, adjust accordingly.
# Let's assume it has a 'filename' column:
# char_df['filename'] = char_df['FilePath'].apply(lambda x: os.path.basename(x)) # if needed

# Select only the columns we want to merge
entropy_cols = ['filename', 'InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy']

# Merge on filename, only keeping rows that exist in char_df
merged = pd.merge(entropy_df[entropy_cols], char_df, on='filename', how='left')

# Save to new CSV
merged.to_csv('datasetupdate2_features.csv', index=False)