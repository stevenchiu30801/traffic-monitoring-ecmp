# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.group_mod_flag = {}

        # monitor
        self.sleep = 2
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tx_pkt_cur = {}    # currently monitoring TX packets
        self.tx_byte_cur = {}   # currently monitoring TX bytes
        self.tx_pkt_int = {}    # TX packets in the last monitoring interval
        self.tx_byte_int = {}    # TX bytes in the last monitoring interval

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)

        self.group_mod_flag[dpid] = True

    def add_flow(self, datapath, hard_timeout, priority, match, actions, buffer_id=None):
    # def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_group_mod(self, datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port_1 = 1
        queue_1 = ofp_parser.OFPActionSetQueue(0)
        actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        queue_2 = ofp_parser.OFPActionSetQueue(0)
        actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if dpid == 513 or dpid == 514:
            # leaf switch
            if in_port == 1 or in_port == 2:
                # packet from spine switch
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                if out_port != ofproto.OFPP_FLOOD:
                    actions = [parser.OFPActionOutput(out_port)]
                    
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    # install a flow to avoid packet_in next time
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 0, 3, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 0, 3, match, actions)

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

                else:
                    actions = [parser.OFPActionOutput(3)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

                    actions = [parser.OFPActionOutput(4)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)                    
            else:
                # packet from host
                # learn a mac address to avoid FLOOD next time.
                self.mac_to_port[dpid][src] = in_port

               	# learning bridge
               	if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
    
                    actions = [parser.OFPActionOutput(out_port)]
    
                    # install a flow to avoid packet_in next time
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 0, 7, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 0, 7, match, actions)
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return
    
                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                if isinstance(ip_pkt, ipv4.ipv4):
                    # load balancing based on traffic monitoring
                    if self.tx_byte_int[dpid][1] > self.tx_byte_int[dpid][2]:
                        out_port = 2
                    else:
                        out_port = 1

                    ip_dst = ip_pkt.dst
                    ip_proto = ip_pkt.proto

                    if ip_proto == 6:
                        # TCP
                        self.logger.debug("Switch %s: TCP packet", dpid)
                        tcp_pkt = pkt.get_protocol(tcp.tcp)
                        dst_port = tcp_pkt.dst_port

                        actions = [parser.OFPActionOutput(out_port)]
                        match = parser.OFPMatch(eth_type=eth.ethertype,
                                                ipv4_dst=ip_dst,
                                                ip_proto=ip_proto,
                                                tcp_dst=dst_port)

                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1000, 5, match, actions, msg.buffer_id)
                            return
                        else:
                            self.add_flow(datapath, 1000, 5, match, actions)

                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data
                
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        return
                    elif ip_proto == 17:
                        # UDP
                        self.logger.debug("Switch %s: UDP packet", dpid)
                        udp_pkt = pkt.get_protocol(udp.udp)
                        dst_port = udp_pkt.dst_port

                        actions = [parser.OFPActionOutput(out_port)]
                        match = parser.OFPMatch(eth_type=eth.ethertype,
                                                ipv4_dst=ip_dst,
                                                ip_proto=ip_proto,
                                                udp_dst=dst_port)

                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1000, 5, match, actions, msg.buffer_id)
                            return
                        else:
                            self.add_flow(datapath, 1000, 5, match, actions)

                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data
                
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        self.logger.info("Switch %s: UDP packets assign to port %d", dpid, out_port)
                        return

                # multipath implementation
                if self.group_mod_flag[dpid] is True:
                    self.send_group_mod(datapath)
                    self.logger.info("send_group_mod")
                    self.group_mod_flag[dpid] = False

                actions = [parser.OFPActionGroup(group_id=50)]
                match = parser.OFPMatch(in_port=in_port,
                                        eth_type=eth.ethertype)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1000, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1000, 1, match, actions)

                # # limit flooding
                # data = None
                # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                #     data = msg.data
                #
                # # assign to port 1
                # out_port = 1
                # actions = [parser.OFPActionOutput(out_port)]
                #
                # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                #                         in_port=in_port, actions=actions, data=data)
                # datapath.send_msg(out)
                #
                # # flood to other port
                # if in_port == 3:
                #     out_port = 4
                #     actions = [parser.OFPActionOutput(out_port)]
                #
                #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                #                             in_port=in_port, actions=actions, data=data)
                #     datapath.send_msg(out)
                # else:
                #     out_port = 3
                #     actions = [parser.OFPActionOutput(out_port)]
                #
                #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                #                             in_port=in_port, actions=actions, data=data)
                #     datapath.send_msg(out)
        else:
            # spine switch
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 0, 3, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 0, 3, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

# ==================================================
#                   Monitor
# ==================================================

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        if dpid == 513 or dpid == 514:
            body = ev.msg.body

            self.logger.info('datapath         '
                             'in-port  eth-dst           '
                             'out-port packets  bytes')
            self.logger.info('---------------- '
                             '-------- ----------------- '
                             '-------- -------- --------')
            for stat in sorted([flow for flow in body if flow.priority == 1],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):
                self.logger.info('%016x %8x %17s %8x %8d %8d',
                                 ev.msg.datapath.id,
                                 stat.match['in_port'], stat.match['eth_dst'],
                                 stat.instructions[0].actions[0].port,
                                 stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        if dpid == 513:
            self.logger.info('datapath         port     tx-pkts  tx-bytes')
            self.logger.info('---------------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            # self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
            #                  ev.msg.datapath.id, stat.port_no,
            #                  stat.rx_packets, stat.rx_bytes, stat.rx_errors,
            #                  stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            port_no = stat.port_no
            self.tx_pkt_cur.setdefault(dpid, {})
            self.tx_byte_cur.setdefault(dpid, {})
            self.tx_pkt_int.setdefault(dpid, {})
            self.tx_byte_int.setdefault(dpid, {})

            if port_no in self.tx_pkt_cur[dpid]:
                self.tx_pkt_int[dpid][port_no] = stat.tx_packets - self.tx_pkt_cur[dpid][port_no]
                if self.tx_pkt_int[dpid][port_no] < 0:
                    self.logger.warning('Negative value of interval TX packets')
            self.tx_pkt_cur[dpid][port_no] = stat.tx_packets

            if port_no in self.tx_byte_cur[dpid]:
                self.tx_byte_int[dpid][port_no] = stat.tx_bytes - self.tx_byte_cur[dpid][port_no]
                if self.tx_byte_int[dpid][port_no] < 0:
                    self.logger.warning('Negative value of interval TX bytes')
            self.tx_byte_cur[dpid][port_no] = stat.tx_bytes

            if dpid == 513:
                if port_no in self.tx_pkt_int[dpid] and port_no in self.tx_byte_int[dpid]:
                    self.logger.info('%016x %8x %8d %8d', dpid, port_no,
                                    self.tx_pkt_int[dpid][port_no],
                                    self.tx_byte_int[dpid][port_no])
