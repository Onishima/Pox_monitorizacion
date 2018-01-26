import subprocess
import time
import numpy as np

s = np.random.poisson(3,20)
print s
for x in range(len(s)):
  subprocess.call(['./launch_clients'])
  time.sleep(s[x])
