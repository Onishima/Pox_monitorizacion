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
# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}
D = {}
IDthread = 1

# To send out all ports, we can use either of the special ports
# OFPP_FLOOD or OFPP_ALL.  We'd like to just use OFPP_FLOOD,
# but it's not clear if all switches support this, so we make
# it selectable.
all_ports = of.OFPP_FLOOD

def envio_paquete_sonda(event,eth_packet,dst_port):
  while True:
    time.sleep(10)
    log.debug("ENVIO PAQUETE SONDAAAAAAAAAAAAAA")

    icmp=pkt.icmp()
    icmp.type=pkt.TYPE_ECHO_REQUEST
    echo=pkt.ICMP.echo(payload=str(time.time()))
    icmp.payload=echo

    ip_packet = eth_packet.payload
    i = pkt.ipv4(protocol=pkt.ipv4.ICMP_PROTOCOL,srcip=ip_packet.srcip,dstip=ip_packet.dstip)
    i.tos = 0x64
    i.set_payload(icmp)

    e = pkt.ethernet(type=pkt.ethernet.IP_TYPE,src=eth_packet.src,dst=eth_packet.dst)
    e.set_payload(i)

    msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = dst_port))
    event.connection.send(msg)
    log.debug("SE ENVIA PAQUETE SONDA: TOS: %s IP_SRC: %s IP_DEST: %s PROTOCOLO: %s PORT: %s" % (i.tos,ip_packet.srcip,ip_packet.dstip,pkt.ipv4.ICMP_PROTOCOL, event.port))


def instalacion_regla_arp(event,eth_packet,dst_port):
  msg = of.ofp_flow_mod()
  msg.match.dl_dst = eth_packet.src
  #msg.match.dl_src = eth_packet.dst
  msg.match.dl_type = eth_packet.type
  msg.actions.append(of.ofp_action_output(port = event.port))
  event.connection.send(msg)
  # This is the packet that just came in -- we want to
  # install the rule and also resend the packet.
  msg = of.ofp_flow_mod()
  msg.data = event.ofp # Forward the incoming packet
  #msg.match.dl_src = eth_packet.src
  msg.match.dl_dst = eth_packet.dst
  msg.match.dl_type = eth_packet.type
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)
  log.debug("Installing %s <-> %s" % (eth_packet.src, eth_packet.dst))


def creacion_thread(event,eth_packet,dst_port,IDthread):
  threads = list()
  log.debug("NUEVO THREAAAAAAAAAAAAAAD")
  t = threading.Thread(target=envio_paquete_sonda,args=(event,eth_packet,dst_port,),name=IDthread)
  threads.append(t)
  t.start()
  IDthread += 1


def instalacion_regla_ip(event,eth_packet,dst_port,src_port):
  global IDthread

  if eth_packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL and D.get((eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.protocol)) is None:
    D[(eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.protocol)] = IDthread
    creacion_thread(event,eth_packet,dst_port,IDthread)
  elif eth_packet.payload.protocol == pkt.ipv4.TCP_PROTOCOL or eth_packet.payload.protocol == pkt.ipv4.UDP_PROTOCOL:
    if D.get((eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.payload.srcport,eth_packet.payload.payload.dstport,eth_packet.payload.protocol)) is None:
      D[(eth_packet.src,eth_packet.dst,eth_packet.payload.srcip,eth_packet.payload.dstip,eth_packet.payload.payload.srcport,eth_packet.payload.payload.dstport,eth_packet.payload.protocol)] = IDthread
      creacion_thread(event,eth_packet,dst_port,IDthread)

  log.debug(D)
  msg = of.ofp_flow_mod()
  msg.match.dl_type = eth_packet.type
  ip_packet = eth_packet.payload
  msg.match.nw_dst = ip_packet.srcip
  msg.match.nw_src = ip_packet.dstip
  if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
  elif ip_packet.protocol == pkt.ipv4.TCP_PROTOCOL or ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
    msg.match.nw_proto = ip_packet.protocol
    l4_packet = ip_packet.payload
    msg.match.tp_dst = l4_packet.srcport
    msg.match.tp_src = l4_packet.dstport
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
  msg.priority = 10000
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)
 
# Handle messages the switch has sent us because it has no
# matching rule.
def _handle_PacketIn (event):
  #time when the packet is received
  tr = time.time()
  eth_packet = event.parsed
  log.debug("EL CONTROLADOR RECIBE UN PAQUETE")
  # Learn the source
  table[(event.connection,eth_packet.src)] = event.port
  src_port = table.get((event.connection,eth_packet.src))
  dst_port = table.get((event.connection,eth_packet.dst))
  log.debug("EVENT_CONNECTION: %s , PACKET_DST: %s , SRC_PORT: %s DST_PORT: %s" % (event.connection, eth_packet.dst, src_port, dst_port))
  if dst_port is None:
    log.debug("ENTRAMOS EN FLOODING")
    # We don't know where the destination is yet.  So, we'll just
    # send the packet out all ports (except the one it came in on!)
    # and hope the destination is out there somewhere. :)
    #####################PACKET OUT########################
    msg = of.ofp_packet_out(data = event.ofp)
    msg.actions.append(of.ofp_action_output(port = all_ports))
    event.connection.send(msg)
    #######################################################
  else:
    log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
    # Since we know the switch ports for both the source and dest
    # MACs, we can install rules for both directions.
    if eth_packet.type == pkt.ethernet.ARP_TYPE:
	log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
	instalacion_regla_arp(event,eth_packet,dst_port)
    elif eth_packet.type == pkt.ethernet.IP_TYPE:
	if eth_packet.payload.tos == 0x64:
	  #time when the packet was created
	  tc = eth_packet.payload.payload.payload.payload
	  delay = tr - float(tc)
	  log.debug("TIEMPO EN EL QUE FUE CREADO: %s TIEMPO EN EL QUE ES RECIBIDO: %s Delay: %s" % (tc,tr,delay))
	else:
	  log.debug("ENTRAMOS EN LA INSTALACION DE REGLAS")
	  instalacion_regla_ip(event,eth_packet,dst_port,src_port)

def launch (disable_flood = False):
  global all_ports
  if disable_flood:
    all_ports = of.OFPP_ALL

  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Pair-Learning switch running.")

