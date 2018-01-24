import socket
import time

TCP_IP = '10.0.0.2'
TCP_PORT = 12000
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
while 1:
  time.sleep(0.1)
  s.send(MESSAGE)
  data = s.recv(BUFFER_SIZE)
s.close()

print "received data:", data
