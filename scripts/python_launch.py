import subprocess
import time
import numpy as np


n=53
Y=60.0
np.random.seed(1)
s = np.random.poisson(1.0,n)
np.random.seed(1)
duracion_exp = np.random.exponential(Y, n)
print duracion_exp
for x in range(n):
  #print duracion_exp[x]
  if int(duracion_exp[x]) < 15:
    #print "MONGOLO"
    #print int(duracion_exp[x])
    duracion_exp[x] = 15.0
  print str(int(duracion_exp[x])*1000)
  subprocess.call(['./launch_clients_2', str(int(duracion_exp[x])*1000)])
  time.sleep(s[x])
"""
n=53
np.random.seed(1)
s = np.random.poisson(1.0,n)
print s
for x in range(len(s)):
  subprocess.call(['./launch_clients'])
  time.sleep(s[x])
"""
