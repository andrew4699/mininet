# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
  "cores21": ("", '00:11:22:33:44:55')
}

class Part4Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def is_cores21(self):
    return self.connection.dpid == 21

  def allow_all(self):
    match = of.ofp_match()
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    fm.priority = 150
    self.connection.send(fm)

  def block_icmp_hnotrust1(self):
    match = of.ofp_match()
    match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
    match.dl_type = pkt.ethernet.IP_TYPE
    match.set_nw_src(IPS["hnotrust"][0])
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.priority = 200
    self.connection.send(fm)

  def block_ip_hnotrust1_to_dcs31(self):
    match = of.ofp_match()
    match.dl_type = pkt.ethernet.IP_TYPE
    match.set_nw_src(IPS["hnotrust"][0])
    match.set_nw_dst(IPS["serv1"][0])
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.priority = 201
    self.connection.send(fm)

  def route_to_port(self, host, port):
    match = of.ofp_match()
    match.set_nw_dst(IPS[host][0])
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.actions.append(of.ofp_action_output(port = port))
    self.connection.send(fm)

  def s1_setup(self):
    self.allow_all()

  def s2_setup(self):
    self.allow_all()

  def s3_setup(self):
    self.allow_all()

  def dcs31_setup(self):
    self.allow_all()

  def cores21_setup(self):
    self.block_icmp_hnotrust1()
    self.block_ip_hnotrust1_to_dcs31()

  def install_ip_hop_new(self, ipaddr, dstMAC, in_port):
    rule = of.ofp_flow_mod()
    rule.priority = 100
    rule.match.dl_type=pkt.ethernet.IP_TYPE
    rule.match.nw_dst = ipaddr
    # Update the src and dst mac addresses (router -> dst_mac)
    rule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(IPS["cores21"][1])))
    rule.actions.append(of.ofp_action_dl_addr.set_dst(dstMAC))
    rule.actions.append(of.ofp_action_output(port=in_port))
    self.connection.send(rule)

  def handle_arp_request(self, event):
    packet = event.parsed

    reply = arp()
    reply.hwsrc = EthAddr(IPS["cores21"][1]) # 00:....:00:06
    reply.hwdst = packet.src # it just clones it
    reply.opcode = arp.REPLY
    print("protodst", packet.payload.protodst)
    reply.protosrc = packet.payload.protodst
    reply.protodst = packet.payload.protosrc

    net = ethernet()
    net.type = ethernet.ARP_TYPE
    net.src = EthAddr(IPS["cores21"][1])
    net.dst = packet.src
    net.payload = reply

    # install a rule
    # packet.src = src MAC address
    # packet.payload.protosrc = src IP address

    print("packet.payload.protosrc", packet.payload.protosrc)
    print("packet.payload.protodst", packet.payload.protodst)
    print("packet.src", packet.src)
    print("packet.dst", packet.dst)
    print("packet.payload.hwsrc", packet.payload.hwsrc)
    print("packet.payload.hwdst", packet.payload.hwdst)

    self.install_ip_hop_new(packet.payload.protosrc, packet.src, event.port)
    self.resend_packet(net.pack(), event.port)

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    if self.is_cores21():
      if packet.type == packet.ARP_TYPE:
        print("ARP")
        self.handle_arp_request(event)
        return
      elif packet.type == packet.IP_TYPE:
        print("IP")
        # print("packet.payload.protosrc", packet.payload.protosrc)
        # print("packet.payload.protodst", packet.payload.protodst)
        print("packet.src", packet.src)
        print("packet.dst", packet.dst)
        # print("packet.payload.hwsrc", packet.payload.hwsrc)
        # print("packet.payload.hwdst", packet.payload.hwdst)
        print("packet.payload.srcip", packet.payload.srcip)
        print("packet.payload.dstip", packet.payload.dstip)
        # print("dir(packet.payload)", dir(packet.payload))
        # print("dir(packet)", dir(packet))

        # self.install_ip_hop_new(packet, event.port)

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part4Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
