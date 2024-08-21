import requests
import json
import os
import time
import logging
import pandas as pd
from tkinter import messagebox, scrolledtext, ttk
import tkinter as tk
import configparser



# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Load API key from environment variable
config = configparser.ConfigParser()
config.read('C:\\Users\\Analyst\\.config\\config.ini')
API_KEY = config
if not API_KEY:
    logging.error("VirusTotal API key not found in config.ini.")
    raise ValueError("VirusTotal API key not found in config.ini.")


# Define the base URL for the VirusTotal API
BASE_URL = 'https://www.virustotal.com/api/v3/'

# Define the headers for the requests
HEADERS = {
    'x-apikey': API_KEY
}

# Ensure data directory exists
if not os.path.exists('data'):
    os.makedirs('data')

# Generate the csv data (simulated for now)
data = pd.DataFrame({
    'date': ['2021-01-01', '2021-01-02', '2021-01-03', '2021-01-04', '2021-01-05'],
    'type': ['url', 'file', 'ip', 'domain', 'url'],
    'value': ['https://www.example.com', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '8.8.8.8', 'google.com', 'https://www.example.com'],
    'result': ['malicious', 'clean', 'malicious', 'malicious', 'malicious']
})

# Save the DataFrame to a CSV file
data.to_csv('data/vt_data.csv', index=False)

# Create a root window
root = tk.Tk()
root.title("VirusTotal Data Analysis")
root.geometry("1000x700")
root.resizable(False, False)

# Create a Treeview widget for displaying data
tree = ttk.Treeview(root, columns=list(data.columns), show='headings')
tree.pack(fill=tk.BOTH, expand=True)

# Add column headers
for col in data.columns:
    tree.heading(col, text=col, command=lambda _col=col: sort_column(_col, False))

# Add data to Treeview
def load_data(df):
    tree.delete(*tree.get_children())
    for _, row in df.iterrows():
        tree.insert("", tk.END, values=list(row))

load_data(data)

# Add a scrollbar
scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Sorting function
def sort_column(col, reverse):
    data.sort_values(by=col, ascending=not reverse, inplace=True)
    load_data(data)
    tree.heading(col, command=lambda: sort_column(col, not reverse))

# Filter data function
def filter_data():
    result_type = filter_combobox.get()
    filtered_data = data[data['result'] == result_type]
    load_data(filtered_data)

# Display statistics function
def show_stats():
    stats = data.describe(include='all').to_string()
    messagebox.showinfo("Summary Statistics", stats)

# Show unique values function
def show_unique_values():
    selected_col = column_combobox.get()
    unique_values = data[selected_col].unique()
    messagebox.showinfo("Unique Values", f"Unique values in {selected_col}:\n{unique_values}")

# Count values function
def count_values():
    selected_col = column_combobox.get()
    value_counts = data[selected_col].value_counts().to_string()
    messagebox.showinfo("Value Counts", f"Value counts in {selected_col}:\n{value_counts}")

# Show missing values function
def show_missing_values():
    missing_values = data.isnull().sum().to_string()
    messagebox.showinfo("Missing Values", f"Missing values in each column:\n{missing_values}")

# Export filtered data function
def export_filtered_data():
    export_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if export_path:
        filtered_data = data[data['result'] == filter_combobox.get()]
        filtered_data.to_csv(export_path, index=False)
        messagebox.showinfo("Export Successful", f"Filtered data has been exported to {export_path}")

# Dropdown for filtering
filter_label = tk.Label(root, text="Filter by Result:")
filter_label.pack(pady=5)

filter_combobox = ttk.Combobox(root, values=['malicious', 'clean'])
filter_combobox.pack(pady=5)

filter_button = tk.Button(root, text="Apply Filter", command=filter_data)
filter_button.pack(pady=5)

# Dropdown for column selection
column_label = tk.Label(root, text="Select Column:")
column_label.pack(pady=5)

column_combobox = ttk.Combobox(root, values=data.columns.tolist())
column_combobox.pack(pady=5)

# Buttons for various analyses
stats_button = tk.Button(root, text="Show Statistics", command=show_stats)
stats_button.pack(pady=5)

unique_button = tk.Button(root, text="Show Unique Values", command=show_unique_values)
unique_button.pack(pady=5)

count_button = tk.Button(root, text="Count Values", command=count_values)
count_button.pack(pady=5)

missing_button = tk.Button(root, text="Show Missing Values", command=show_missing_values)
missing_button.pack(pady=5)

export_button = tk.Button(root, text="Export Filtered Data", command=export_filtered_data)
export_button.pack(pady=5)

root.mainloop()