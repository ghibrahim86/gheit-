'''
Coursera:
- Software Defined Networking (SDN) course
-- Module 4 Programming Assignment

Professor: Nick Feamster
Teaching Assistant: Muhammad Shahbaz
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
import os
import csv
''' Add your imports here ... '''


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ['HOME']

''' Add your global variables here ... '''


class Firewall (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp(self, event):
        ''' Add your logic here ... '''

        i = 0

        reader = csv.reader(open(policyFile))
        for id, mac_0, mac_1 in reader:
            if i != 0:
                fm = of.ofp_flow_mod()
                fm.match = of.ofp_match()
                fm.match.dl_src = EthAddr(mac_0)
                fm.match.dl_dst = EthAddr(mac_1)
                event.connection.send(fm)
            i += 1

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))


def launch():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
