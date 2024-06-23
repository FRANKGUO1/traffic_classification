from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.enableCli()

# Network definition
# net.addP4RuntimeSwitch('s1', cli_input='s1-commands.txt', cpu_port=255)
net.addP4RuntimeSwitch('s1', cpu_port=255)
# net.addP4Switch('s1', cli_input='s1-commands.txt')
net.setP4SourceAll('edge_switch.p4')

net.addHost('h1')
net.addHost('h2')
# net.addHost('server')


net.addLink('h1', 's1')
net.addLink('h2', 's1')
# net.addLink('server', 's1')

# Assignment strategy
net.l3()

# Nodes general options
# net.enableCpuPortAll()
net.enablePcapDumpAll()
net.enableLogAll()

# Start the network
net.startNetwork()