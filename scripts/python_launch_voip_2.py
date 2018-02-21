import subprocess
import time
import numpy as np

n = 15
Y = 60.0
######################################################
######################################################
np.random.seed(2)
duracion_exp = np.random.exponential(Y, n)
print duracion_exp
for x in range(n):
  #print int(duracion_exp[x])*1000
  subprocess.call(['./launch_clients_voip_2', str(int(duracion_exp[x])*1000)])
print "PRIMEROS FLUJOS y PAUSA"
time.sleep(Y)
print "ENVIAMOS NUEVOS FLUJOS"
#######################################################
#######################################################
n = 50
np.random.seed(1)
s = np.random.poisson(1.0,n)
np.random.seed(1)
duracion_exp = np.random.exponential(Y, n)
for x in range(n):
  #print duracion_exp[x]
  subprocess.call(['./launch_clients_voip_2', str(int(duracion_exp[x])*1000)])
  time.sleep(s[x])
#######################################################
#######################################################
