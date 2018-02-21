import subprocess
import time
import numpy as np

np.random.seed(1)
s = np.random.poisson(1.0,50)
print s
np.random.seed(1)
s = np.random.exponential(10.0,10)
print s
for x in range(len(s)):
  print int(s[x])*1000
  subprocess.call(['./launch_clients_2', str(int(s[x])*1000)])
  #print int(s[x])
