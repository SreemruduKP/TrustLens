import pandas as pd

df = pd.read_csv("data/phishing.csv")

# print("\nshape: ", df.shape) #(rows,colums)
# print("\ncolumns: ", df.columns.tolist()) #column names
# print("\nFirst 5 rows: ") 
# print(df.head()) #print first 5 rows
# print("\ndata types:\n", df.info()) #summary , data types, rows cols, RangeIndex : 0 to 11054 here
# print("\nmissing values: \n", df.isnull().sum()) #give numer of missing values in each column

# drop id colum
df = df.drop(columns=["id"])
print("\nAfter dropping id:", df.shape)

# check class balance
print("\nPhishing vs Legitimate:")
print(df["Result"].value_counts())

# save clean dataset
df.to_csv("data/clean_phishing.csv", index=False)
print("\nClean dataset saved!")

