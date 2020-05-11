# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller (object):
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

  def allow_all(self):
    match = of.ofp_match()
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(fm)

  def block_icmp_hnotrust1(self):
    match = of.ofp_match()
    match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
    match.dl_type = pkt.ethernet.IP_TYPE
    match.set_nw_src(IPS["hnotrust"][0])
    fm = of.ofp_flow_mod()
    fm.match = match
    self.connection.send(fm)

  def block_ip_hnotrust1_to_dcs31(self):
    match = of.ofp_match()
    match.dl_type = pkt.ethernet.IP_TYPE
    match.set_nw_src(IPS["hnotrust"][0])
    match.set_nw_dst(IPS["serv1"][0])
    fm = of.ofp_flow_mod()
    fm.match = match
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

  def cores21_setup(self):
    self.block_icmp_hnotrust1()
    self.block_ip_hnotrust1_to_dcs31()
    self.route_to_port("h10", 1)
    self.route_to_port("h20", 2)
    self.route_to_port("h30", 3)
    self.route_to_port("serv1", 4)
    self.route_to_port("hnotrust", 5)

  def dcs31_setup(self):
    self.allow_all()

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

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
