#!/usr/bin/python

# 2-by-2 leaf-spine topology
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, Host
from mininet.link import TCLink
from mininet.log import setLogLevel

class MyTopo(Topo):

    spineswitch = []
    leafswitch = []
    host = []

    def __init__(self):

        # initialize topology
        Topo.__init__(self)

        for i in range(1, 3):
            # add spine switches
            self.spineswitch.append(self.addSwitch("10"+str(i), dpid="000000000000010"+str(i)))

            # add leaf switches
            self.leafswitch.append(self.addSwitch("20"+str(i), dpid="000000000000020"+str(i)))

        # add hosts
        self.host.append(self.addHost("301", mac="00:00:00:00:00:01", ip="10.0.0.1/24"))
        self.host.append(self.addHost("302", mac="00:00:00:00:00:02", ip="10.0.0.2/24"))
        self.host.append(self.addHost("303", mac="00:00:00:00:00:03", ip="10.0.0.3/24"))
        self.host.append(self.addHost("304", mac="00:00:00:00:00:04", ip="10.0.0.4/24"))

        # add links
        for i in range(2):
            self.addLink(self.spineswitch[i], self.leafswitch[0], 1, i+1)
            self.addLink(self.spineswitch[i], self.leafswitch[1], 2, i+1)

        for i in range(2):
            self.addLink(self.leafswitch[i], self.host[i*2], 3)
            self.addLink(self.leafswitch[i], self.host[i*2+1], 4)

topos = {'mytopo': (lambda: MyTopo())}

if __name__ == "__main__":
    setLogLevel('info')

    topo = MyTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1')

    net.start()
    CLI(net)
    net.stop()
