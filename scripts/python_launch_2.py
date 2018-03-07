import subprocess
import time
import numpy as np

n = 10
Y = 40.0
######################################################
######################################################
print duracion_exp
for x in range(n):
  #print int(duracion_exp[x])*1000
  subprocess.call(['./launch_clients'])
print "PRIMEROS FLUJOS y PAUSA"
time.sleep(Y)
print "ENVIAMOS NUEVOS FLUJOS"
#######################################################
#######################################################
n=53
np.random.seed(3)
s = np.random.poisson(1.0,n)
for x in range(n):
  #print duracion_exp[x]
  subprocess.call(['./launch_clients'])
  time.sleep(s[x])
#######################################################
#######################################################
