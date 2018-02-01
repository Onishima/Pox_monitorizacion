# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A super simple OpenFlow learning switch that installs rules for
each pair of L2 addresses.
"""

# These next two imports are common POX convention
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import threading
import time
import pox.openflow.switch_ports as swpo
from random import shuffle, random, uniform, randrange

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

SKYPE = 0.3
# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}
D = {}
IDthread = 1
time_sleep = 5
# To send out all ports, we can use either of the special ports
# OFPP_FLOOD or OFPP_ALL.  We'd like to just use OFPP_FLOOD,
# but it's not clear if all switches support this, so we make
# it selectable.
all_ports = of.OFPP_FLOOD

def envio_paquete_sonda(event,eth_packet,dst_port,src_port):
  global time_sleep
  while True:
    time.sleep(time_sleep)
    #log.debug("ENVIO PAQUETE SONDAAAAAAAAAAAAAA")
    icmp=pkt.icmp()
    icmp.type=pkt.TYPE_ECHO_REQUEST
    for interface in swpo.d[event.connection.dpid]:
    	list1 = [time.time(),event.connection.dpid,interface]
    	str1 = ','.join(str(j) for j in list1)
    	echo=pkt.ICMP.echo(payload=str1)
    	icmp.payload=echo

    	ip_packet = eth_packet.payload
    	i = pkt.ipv4(protocol=pkt.ipv4.ICMP_PROTOCOL,srcip=ip_packet.srcip,dstip=ip_packet.dstip)
    	i.tos = 0x64
    	i.set_payload(icmp)

    	e = pkt.ethernet(type=pkt.ethernet.IP_TYPE,src=eth_packet.src,dst=eth_packet.dst)
    	e.set_payload(i)
    	msg = of.ofp_packet_out(in_port=src_port)
    	msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = interface))
        event.connection.send(msg)
    #log.debug("SE ENVIA PAQUETE SONDA: TOS: %s IP_SRC: %s IP_DEST: %s PROTOCOLO: %s PORT: %s" % (i.tos,ip_packet.srcip,ip_packet.dstip,pkt.ipv4.ICMP_PROTOCOL, of.OFPP_ALL))


def instalacion_regla_arp(event,eth_packet,dst_port):
  msg = of.ofp_flow_mod()
  msg.match.dl_dst = eth_packet.src
  msg.match.dl_type = eth_packet.type
  msg.actions.append(of.ofp_action_output(port = event.port))
  event.connection.send(msg)
  # This is the packet that just came in -- we want to
  # install the rule and also resend the packet.
  msg = of.ofp_flow_mod()
  msg.data = event.ofp # Forward the incoming packet
  msg.match.dl_dst = eth_packet.dst
  msg.match.dl_type = eth_packet.type
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)
  log.debug("Installing %s <-> %s" % (eth_packet.src, eth_packet.dst))


def creacion_thread(event,eth_packet,dst_port,src_port,IDthread):
  threads = list()
  #log.debug("NUEVO THREAAAAAAAAAAAAAAD")
  t = threading.Thread(target=envio_paquete_sonda,args=(event,eth_packet,dst_port,src_port,),name=IDthread)
  threads.append(t)
  t.start()
  IDthread += 1


def instalacion_regla_ip(event,eth_packet,dst_port,src_port):
  global IDthread

  if eth_packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL and D.get((eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.protocol)) is None:
    D[(eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.protocol)] = IDthread
    creacion_thread(event,eth_packet,dst_port,src_port,IDthread)


  ip_packet = eth_packet.payload
  if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
    if str(eth_packet.payload.srcip) in swpo.switch_host[str(event.connection.dpid)].keys():
      if not str(ip_packet.srcip) in swpo.src_dst_app.keys():
        for interface in swpo.d[event.connection.dpid]:
          swpo.src_dst_app[str(ip_packet.srcip)][str(ip_packet.dstip)][interface] = [round(uniform(0.0, 1.0),1),round(uniform(0.0, 1.0),1),round(uniform(0.0, 1.0),1)]
    elif str(eth_packet.payload.dstip) in swpo.switch_host[str(event.connection.dpid)].keys():
      if not str(ip_packet.dstip) in swpo.src_dst_app.keys():
        for interface in swpo.d[event.connection.dpid]:
          swpo.src_dst_app[str(ip_packet.dstip)][str(ip_packet.srcip)][interface] = [round(uniform(0.0, 1.0),1),round(uniform(0.0, 1.0),1),round(uniform(0.0, 1.0),1)]


  log.debug(D)
  msg = of.ofp_flow_mod()
  msg.match.dl_type = eth_packet.type
  msg.match.nw_dst = ip_packet.srcip
  msg.match.nw_src = ip_packet.dstip
  if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
  elif ip_packet.protocol == pkt.ipv4.TCP_PROTOCOL or ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
    l4_packet = ip_packet.payload
    msg.match.tp_dst = l4_packet.srcport
    msg.match.tp_src = l4_packet.dstport
    msg.hard_timeout = 52
  msg.priority = 10000
  msg.actions.append(of.ofp_action_output(port = event.port))
  event.connection.send(msg)

  msg = of.ofp_flow_mod()
  msg.data = event.ofp # Forward the incoming packet
  msg.match.dl_type = eth_packet.type
  ip_packet = eth_packet.payload
  msg.match.nw_src = ip_packet.srcip
  msg.match.nw_dst = ip_packet.dstip
  if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
  elif ip_packet.protocol == pkt.ipv4.TCP_PROTOCOL or ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
    l4_packet = ip_packet.payload
    msg.match.tp_src = l4_packet.srcport
    msg.match.tp_dst = l4_packet.dstport
    msg.hard_timeout = 52
  msg.priority = 10000
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)

def actualizar_q_values(eth_packet, switch, switch_interface, delay, delay_max, app):
  q_use = 0.0
  if delay < delay_max:
    q_use = 0.0
  elif delay > (delay_max+1):
    q_use = 1.0
  else:
    q_use = delay - delay_max
  q_use_current = swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(switch_interface)][app]
  swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(switch_interface)][app] = round(q_use_current + 0.85*(q_use - q_use_current),2)

# Handle messages the switch has sent us because it has no
# matching rule.
def _handle_PacketIn (event):
  global time_sleep
  #time when the packet is received
  tr = time.time()
  eth_packet = event.parsed
  #log.debug("#######################################################")
  #log.debug("###################_HANDLE_PACKETIN####################")
  #log.debug("#######################################################")
  # Learn the source
  table[(event.connection,eth_packet.src)] = event.port
  src_port = table.get((event.connection,eth_packet.src))
  dst_port = table.get((event.connection,eth_packet.dst))
  log.debug("EVENT_CONNECTION: %s , PACKET_DST: %s , SRC_PORT: %s DST_PORT: %s" % (event.connection, eth_packet.dst, src_port, dst_port))
  if dst_port is None:
    log.debug("ENTRAMOS EN FLOODING")
    log.debug("SRC: %s , DST: %s" % (eth_packet.src,eth_packet.dst))
    # We don't know where the destination is yet.  So, we'll just
    # send the packet out all ports (except the one it came in on!)
    # and hope the destination is out there somewhere. :)
    #####################PACKET OUT########################
    msg = of.ofp_packet_out(data = event.ofp)
    msg.actions.append(of.ofp_action_output(port = all_ports))
    event.connection.send(msg)
    #######################################################
  else:
    # Since we know the switch ports for both the source and dest
    # MACs, we can install rules for both directions.
    if eth_packet.type == pkt.ethernet.ARP_TYPE:
	#log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
	instalacion_regla_arp(event,eth_packet,dst_port)
    elif eth_packet.type == pkt.ethernet.IP_TYPE:
	if eth_packet.payload.tos == 0x64:
	  log.debug("SE RECIBE UN PAQUETE SONDA")
	  #time when the packet was created
	  str2 = eth_packet.payload.payload.payload.payload
	  list2 = str2.split(',')
	  #log.debug("PAYLOAD: %s", list2)
	  delay = tr - float(list2[0])
	  switch = list2[1]
	  switch_interface = list2[2]
	  swpo.sw_int_delay[switch][switch_interface] = delay
	  ###################################################
	  #############Calculo del q_value###################
	  actualizar_q_values(eth_packet,switch,switch_interface,delay,0.3,0)
	  actualizar_q_values(eth_packet,switch,switch_interface,delay,0.3,1)
          actualizar_q_values(eth_packet,switch,switch_interface,delay,0.7,2)
	  ###################################################
	  #log.debug("Paquete recibido por el switch %s , enviado por su interfaz %s con un delay total %s" % (switch,switch_interface,delay))
	  log.debug("SW_INT_DELAY: %s" % (swpo.sw_int_delay))
	  log.debug("SRC_DST_APP: %s" % (swpo.src_dst_app))
	  #log.debug("TIEMPO EN EL QUE FUE CREADO: %s TIEMPO EN EL QUE ES RECIBIDO: %s Delay: %s" % (list2[0],tr,delay))
	else:
	  #log.debug("SE RECIBE UN PAQUETE COMUN")
	  if eth_packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL or eth_packet.payload.protocol == pkt.ipv4.UDP_PROTOCOL:
	    tcp_udp_port = eth_packet.payload.payload.dstport
	    """
	    if eth_packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL:
	      log.debug("PROTOCOLO TCP")
	    elif eth_packet.payload.protocol == pkt.ipv4.UDP_PROTOCOL:
	      log.debug("PROTOCOLO UDP")
            """
	    #log.debug("IP SRC: %s , IP DST: %s" % (eth_packet.payload.srcip,eth_packet.payload.dstip))
	    #log.debug("PORT SRC: %s , PORT DST: %s" % (eth_packet.payload.payload.srcport, eth_packet.payload.payload.dstport))
	    q_use = 0
	    dst_port_rl = 0
	    q_use_min = 1.0


	    ###################################
	    ################APP1###############
	    if tcp_udp_port == 12000:
	      #log.debug("PAQUETE 12000!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	      if str(eth_packet.payload.srcip) in swpo.switch_host[str(event.connection.dpid)].keys():
		 #log.debug("swpo.sw_int_delay[event.connection.dpid].keys(): %s" % swpo.sw_int_delay[str(event.connection.dpid)].keys())
		 list_int = [] #lista de interfaces que cumplen los requisitos de la aplicacion
		 for key2 in swpo.sw_int_delay[str(event.connection.dpid)].keys():
		   if swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(key2)][0] == 0.0:
		     list_int.append(int(key2))
		   if swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(key2)][0] < q_use_min:
		     dst_port_rl = int(key2)
		     q_use_min = swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(key2)][0]
		     #log.debug("dst_port_rl: %s , q_use_min: %s" % (dst_port_rl, q_use_min))
		 if len(list_int) != 0:
		   random_index = randrange(0,len(list_int))
		   dst_port = list_int[random_index]
		   log.debug(list_int)
		   #log.debug("DST_PORT: %s" % (dst_port))
		 else:
		   dst_port = dst_port_rl
	      else:
		src_port = event.port
	      #log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
              instalacion_regla_ip(event,eth_packet,dst_port,src_port)


            ###################################
            ################APP2###############
            elif tcp_udp_port == 13000:
              log.debug("PAQUETE 13000!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
              if str(eth_packet.payload.srcip) in swpo.switch_host[str(event.connection.dpid)].keys():
                 for key2 in swpo.sw_int_delay[str(event.connection.dpid)].keys():
                   if swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(key2)][1] < q_use_min:
                     dst_port_rl = int(key2)
                     q_use_min = swpo.src_dst_app[str(eth_packet.payload.srcip)][str(eth_packet.payload.dstip)][int(key2)][1]
                 dst_port = dst_port_rl
              else:
                src_port = event.port
              log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
              instalacion_regla_ip(event,eth_packet,dst_port,src_port)
	    ###################################
            ###################################


	    else: #instalar las reglas necesarias si no es ninguna de las aplicaciones predefinidas
	      log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
              instalacion_regla_ip(event,eth_packet,dst_port,src_port)

	  else: #instalar las reglas si el flujo no es TCP o UDP
	    log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
            instalacion_regla_ip(event,eth_packet,dst_port,src_port)

def launch (disable_flood = False):
  global all_ports
  if disable_flood:
    all_ports = of.OFPP_ALL

  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Pair-Learning switch running.")

