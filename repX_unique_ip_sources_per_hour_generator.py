# library imports
import numpy as np
import pandas as pd  
import matplotlib.pyplot as plt 
import matplotlib.dates as mdate

# loading data from CSV file
dataset = pd.read_csv('workfiles/global_last10years.csv')

#create a list with packets_per_day
ts_packets = dataset['# Unique Source IPs'].tolist()

ts_packets = [float(x) if str(x).strip() != '' else 0.0 for x in ts_packets]  # Convert to integers if necessary

#create a list with the timestamps
raw = pd.to_datetime(dataset['timestamp'], unit='s')

# creating the plotting environment
fig, ax = plt.subplots()

# formating axes, ticks and ticklabels for timestamps
timestamps = mdate.date2num(raw)
date_fmt = '%y-%m-%d' #for full date: date_fmt = '%d-%m-%y %H:%M:%S'
date_formatter = mdate.DateFormatter(date_fmt)
ax.xaxis.set_major_formatter(date_formatter)
ax.xaxis_date()
fig.autofmt_xdate()

# title and x,y-labels
plt.xlabel('days of observed time span')
plt.ylabel('#uIPs/hour [millions]')
plt.title('Number of unique IP sources per hour (daily average)')

# plot stem graphic
plt.stem(timestamps, [(x / (10**6)) for x in ts_packets], linefmt='C0-', markerfmt=" ", basefmt=" ")
plt.grid()
plt.savefig("output/team29_Ex3_uIPs-hour.png")
plt.show()
