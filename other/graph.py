import matplotlib.pyplot as plt
import pandas as pd
import sys

if len(sys.argv) == 1:
    print("no file")
    exit()

cover_data = pd.read_csv(sys.argv[1])
cover_data = cover_data.drop(columns=['Milliseconds'])

#frames = [cover_data]
#df = pd.concat(frames)
#df.plot(x='Seconds')
#plt.show()
if len(sys.argv) != 3:
    plt.plot('Seconds', 'MemCover', data=cover_data)
    plt.plot('Seconds', 'Cover', data=cover_data)
elif sys.argv[2] == 'c':
    plt.plot('Seconds', 'Cover', data=cover_data)
elif sys.argv[2] == 'm':
    plt.plot('Seconds', 'MemCover', data=cover_data)
else:
    print("wrong arg")
    exit()

plt.legend()    
plt.show()

