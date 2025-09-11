import pandas as pd
import sys

if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <data_file.csv>")
    sys.exit(1)

data_file = sys.argv[1]
df = pd.read_csv(data_file)

# Replace 'filename' with the actual column name that contains the file path
df['label'] = df['filename'].apply(
    lambda x: 1 if 'webshell' in x else (0 if 'benign' in x else -1)
)

# Move 'label' to the last column
cols = [col for col in df.columns if col != 'label'] + ['label']
df = df[cols]

df.to_csv('complete_data_features_labeled.csv', index=False)