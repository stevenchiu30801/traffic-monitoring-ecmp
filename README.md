# ECMP Based on Traffic Monitoring

This respository is the project during SDN/NFV course at NCTU in 2018 Spring.

## Introduction

With the limitation of load balancing with hash function or other algorithm according to packet header fields, in this porject I present a dynamically scheduling mechanism based on traffic monitoring.

Each switch or router periodically monitors the traffic status of ports and determines next-hop of packets by choosing the least loaded link when flows come in.

In the case of multiple elephant flows between two end devices and with same protocol stacks, such as one user requests for large files from a FTP server, our method can distribute flows to multipaths in a more efficient way.

In the implementation, I use Mininet and run the application on Ryu controller.

## Prerequisites

You can install [Mininet](https://github.com/mininet/mininet) and [Ryu](https://github.com/osrg/ryu) from their GitHub pages.

## Usage

In the project, I experiment with a 2x2 leaf-spine topology on Mininet. Each leaf node have two hosts connected to it.

Build up the network environment. You should run with `sudo` permission.
```
$ sudo ./2x2LeafSpine.py
```

At the Mininet shell, open a terminal for the controller.
```
mininet> xterm c0
```
After executing the command, a xterm for `c0` controller will pop up.

Run the Ryu application at `c0` shell.
```
c0$ ryu run traffic-monitoring-ecmp.py
```
Now logs of port tranmitted volumn on leaf switch `201` will be shown and refreshed periodically. 

To test our application, here provides two UDP file transmission script `sender` and `receiver`. For the demonstration, first run `receiver` on host `303` or `304` to listen on a specified port, and then execute `sender` on host `301` or `302`.

Open a shell for host `303`.
```
mininet> xterm 303
```

Run `receiver` script on host `303`.
```
303$ ./receiver <port_to_listen> <saved_filename>
```

Also open a shell for host `301`.
```
mininet> xterm 301
```

Run `sender` script on host `301`.
```
301$ ./sender <receiver_ip> <receiver_port> <transmitted_filename>
```

Now the file should start to be transmitted and you can see the log for transmitted packets and bytes at controller `c0` terminal.

Try to transmit two large files to create elephant flows, and see if they are distributed to different ports. Aslo perform the same procedure with the application `traditional-ecmp.py` to see the difference.

## Details
For more details, please refer to [paper.docx](https://github.com/stevenchiu30801/traffic-monitoring-ecmp/blob/master/paper.docx) or [slides.pptx](https://github.com/stevenchiu30801/traffic-monitoring-ecmp/blob/master/slides.pptx).
