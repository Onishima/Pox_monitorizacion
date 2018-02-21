import subprocess
import time
import numpy as np

"""
n=50
Y=60.0
np.random.seed(1)
s = np.random.poisson(1.0,n)
np.random.seed(1)
duracion_exp = np.random.exponential(Y, n)
for x in range(n):
  #print duracion_exp[x]
  subprocess.call(['./launch_clients_voip_2', str(int(duracion_exp[x])*1000)])
  time.sleep(s[x])
"""

n = 50
s = np.random.poisson(1.0,n)
print s
for x in range(len(s)):
  subprocess.call(['./launch_clients_voip'])
  time.sleep(s[x])
