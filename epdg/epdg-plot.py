import re
import matplotlib.pyplot as plt

# Define a regular expression pattern to extract MCC from FQDN
pattern = r"mcc(\d+)\."

# Define a dictionary to store counts of MCCs
mcc_counts = {}

# Read each FQDN from the list
with open('epdg-fqdn-raw.txt', 'r') as f:
    for line in f:
        # Extract MCC from FQDN using regex
        match = re.search(pattern, line)
        if match:
            mcc = match.group(1)
            # Increment the count for this MCC
            mcc_counts[mcc] = mcc_counts.get(mcc, 0) + 1

# Plot the distribution of MCCs
plt.bar(mcc_counts.keys(), mcc_counts.values())
plt.xlabel('Mobile Country Code (MCC)')
plt.ylabel('Count')
plt.title('Distribution of MCCs')
plt.show()
