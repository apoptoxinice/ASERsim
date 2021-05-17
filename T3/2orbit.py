#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    info( '*** Add switches\n')
    r6 = net.addHost('r6', cls=Node, ip='0.0.0.0')
    r6.cmd('sysctl -w net.ipv4.ip_forward=1')
    r10 = net.addHost('r10', cls=Node, ip='0.0.0.0')
    r10.cmd('sysctl -w net.ipv4.ip_forward=1')
    r4 = net.addHost('r4', cls=Node, ip='0.0.0.0')
    r4.cmd('sysctl -w net.ipv4.ip_forward=1')
    r5 = net.addHost('r5', cls=Node, ip='0.0.0.0')
    r5.cmd('sysctl -w net.ipv4.ip_forward=1')
    r11 = net.addHost('r11', cls=Node, ip='0.0.0.0')
    r11.cmd('sysctl -w net.ipv4.ip_forward=1')
    s12 = net.addSwitch('s12', cls=OVSKernelSwitch, failMode='standalone')
    r8 = net.addHost('r8', cls=Node, ip='0.0.0.0')
    r8.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2 = net.addHost('r2', cls=Node, ip='0.0.0.0')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')
    r1 = net.addHost('r1', cls=Node, ip='0.0.0.0')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r9 = net.addHost('r9', cls=Node, ip='0.0.0.0')
    r9.cmd('sysctl -w net.ipv4.ip_forward=1')
    r3 = net.addHost('r3', cls=Node, ip='0.0.0.0')
    r3.cmd('sysctl -w net.ipv4.ip_forward=1')
    r7 = net.addHost('r7', cls=Node, ip='0.0.0.0')
    r7.cmd('sysctl -w net.ipv4.ip_forward=1')

    info( '*** Add hosts\n')

    info( '*** Add links\n')
    net.addLink(r1, r2)
    net.addLink(r2, r3)
    net.addLink(r3, r4)
    net.addLink(r4, r5)
    net.addLink(r5, r6)
    net.addLink(r6, r7)
    net.addLink(r7, r8)
    net.addLink(r8, r9)
    net.addLink(r9, r10)
    net.addLink(r10, r11)
    net.addLink(r11, r1)
    net.addLink(s12, r4)
    net.addLink(s12, r5)
    net.addLink(s12, r6)
    net.addLink(s12, r7)
    net.addLink(s12, r8)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s12').start([])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

