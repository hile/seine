"""
Parse netstat -s output fields from linux, OS/X and FreeBSD
"""

import fnmatch
import os
import re
import sys
import time

from datetime import datetime
from subprocess import Popen, PIPE

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
RE_PROTOCOL = re.compile('^[a-zA-Z0-9]+:$')


COUNTER_REGEXPS = (
    re.compile('^(?P<value>\d+)\s+(?P<name>.*)\s+\([a-z]*\s*(?P<counter>\d+)\s+(?P<countername>[^)]+)\)\s+(?P<name_continued>.*)$'),
    re.compile('^(?P<value>\d+)\s+(?P<name>.*)\s+\([a-z]*\s*(?P<counter>\d+)\s+(?P<countername>[^)]+)\)$'),
    re.compile('^(?P<value>\d+)\s+(?P<name>.*)$'),
    re.compile('^(?P<name>.*):\s+(?P<value>\d+)$'),
)

NETSTAT_PROTOCOL_COUNTERS_LINUX = {

    'icmp': {
        'counter_map': {
            'ICMP messages received':       { 'group': 'received', 'name': 'messages' },
            'input ICMP message failed.':   { 'group': 'received', 'name': 'failed' },
            'ICMP messages sent':           { 'group': 'sent',     'name': 'messages' },
            'ICMP messages failed':         { 'group': 'sent',     'name': 'failed' },
        },

        'histogram_map': {

            'ICMP output histogram:': {
                'group': 'summary',
                'name': 'output',
                'counter_map': {
                    'destination unreachable': { 'group': 'sent', 'name': 'destination_unreachable' },
                    'echo requests': { 'group': 'sent', 'name': 'echo_requests' },
                    'echo replies': { 'group': 'sent', 'name': 'echo_replies' },
                },
            },

            'ICMP input histogram:': {
                'group': 'summary',
                'name': 'input',
                'counter_map': {
                    'destination unreachable': { 'group': 'received', 'name': 'destination_unreachable' },
                    'echo requests': { 'group': 'received', 'name': 'echo_requests' },
                    'echo replies': { 'group': 'received', 'name': 'echo_replies' },
                },
            },

        },

    },

    'icmpmsg': {
        'counter_map': {
            'InType0':  { 'group': 'received', 'name': 'echo_reply' },
            'InType3':  { 'group': 'received', 'name': 'destination_unreachable' },
            'InType8':  { 'group': 'received', 'name': 'echo_request' },
            'OutType0': { 'group': 'sent', 'name': 'echo_reply' },
            'OutType3': { 'group': 'sent', 'name': 'destination_unreachable' },
            'OutType8': { 'group': 'sent', 'name': 'echo_request' },
        },
    },

    'ip': {
        'counter_map': {
            'total packets received': { 'group': 'stats', 'name': 'packets_received' },
            'with invalid addresses': { 'group': 'stats', 'name': 'invalid_address' },
            'forwarded': { 'group': 'stats', 'name': 'forwarded' },
            'requests sent out': { 'group': 'stats', 'name': 'requests_sent' },
            'incoming packets discarded': { 'group': 'stats', 'name': 'incoming_packets_discarded' },
            'incoming packets delivered': { 'group': 'stats', 'name': 'incoming_packets_delivered' },
        },
    },

    'ipext': {
        'counter_map': {
            'InOctets':            { 'group': 'received',  'name': 'octets' },
            'InMcastPkts':         { 'group': 'received',  'name': 'multicast_packets' },
            'InMcastOctets':       { 'group': 'received',  'name': 'multicast_octets' },
            'InNoECTPkts':         { 'group': 'received',  'name': 'no_ect_packets' },
            'OutOctets':           { 'group': 'sent',      'name': 'octets' },
            'OutMcastPkts':        { 'group': 'sent',      'name': 'multicast_packets' },
            'OutMcastOctets':      { 'group': 'sent',      'name': 'multicast_octets' },
        },
    },

    'tcp': {
        'counter_map': {
            'active connections openings':      { 'group': 'connection', 'name': 'active_connection_openings' },
            'passive connection openings':      { 'group': 'connection', 'name': 'passive_connection_openings' },
            'failed connection attempts':       { 'group': 'connection', 'name': 'failed_connection_attemps' },
            'connection resets received':       { 'group': 'connection', 'name': 'connection_resets_received' },
            'connections established':          { 'group': 'connection', 'name': 'connections_established' },
            'resets sent':                      { 'group': 'connection', 'name': 'resets_sent' },
            'segments received':                { 'group': 'segment',    'name': 'received' },
            'segments send out':                { 'group': 'segment', 'name': 'sent_out' },
            'segments retransmited':            { 'group': 'segment', 'name': 'retransmitted' },
            'bad segments received.':           { 'group': 'segment', 'name': 'bad_segments_received' },
        },
    },

    'tcpext': {
        'counter_map': {
            'Invalid SYN cookies received':                                         { 'group': 'errors', 'name': 'invalid_syn_cookies_received' },
            'resets received for embryonic SYN_RECV sockets':                       { 'group': 'errors', 'name': 'resets_for_embryonic_sync_recv_sockets' },
            'packets pruned from receive queue because of socket buffer overrun':   { 'group': 'errors', 'name': 'socket_buffer_overrun_pruned_from_receive_queue' },
            'packets pruned from receive queue':                                    { 'group': 'errors', 'name': 'pruned_from_receive_queue' },
            'ICMP packets dropped because they were out-of-window':                 { 'group': 'stats',  'name': 'dropped_icmp_out_of_window' },
            'TCP sockets finished time wait in fast timer':                         { 'group': 'stats',  'name': 'finish_time_wait_in_fast_timer' },
            'delayed acks sent':                                                    { 'group': 'stats',  'name': 'delayed_acks_sent' },
            'delayed acks further delayed because of locked socket':                { 'group': 'stats',  'name': 'locked_socket_delayed_acks_further_delayed' },
            'Quick ack mode was activated times':                                   { 'group': 'stats',  'name': 'quick_ack_mode_activated' },
            'packets directly queued to recvmsg prequeue.':                         { 'group': 'stats',  'name': 'packets_directly_queued_to_recvmsg_prequeue' },
            'bytes directly received in process context from prequeue':             { 'group': 'stats',  'name': 'bytes_directly_received_in_process_context_from_prequeue' },
            'packet headers predicted':                                             { 'group': 'stats',  'name': 'packet_headers_predicted' },
            'acknowledgments not containing data payload received':                 { 'group': 'stats',  'name': 'received_acknowledgements_not_containing_data' },
            'acknowledgments not containing data received':                         { 'group': 'stats',  'name': 'ack_no_data_received' },
            'predicted acknowledgments':                                            { 'group': 'stats',  'name': 'predicted_acknowledgements' },
            'times recovered from packet loss due to SACK data':                    { 'group': 'stats',  'name': 'recover_from_packet_loss_due_to_sack_data' },
            'congestion windows fully recovered':                                   { 'group': 'stats',  'name': 'cognestion_windows_fully_recovered' },
            'congestion windows partially recovered using Hoe heuristic':           { 'group': 'stats',  'name': 'cognestion_windows_partially_recovered_using_hoe_heuristic' },
            'congestion windows recovered without slow start after partial ack':    { 'group': 'stats',  'name': 'cognestion_windows_recovered_without_slow_start_after_partial_ack' },
            'congestion windows recovered after partial ack':                       { 'group': 'stats',  'name': 'cognestion_windows_recovered_after_partial_ack' },
            'TCP data loss events':                                                 { 'group': 'stats',  'name': 'data_loss_events' },
            'TCPDSACKUndo':                                                         { 'group': 'stats',  'name': 'sack_undo' },
            'TCPLossProbes':                                                        { 'group': 'stats',  'name': 'loss_probes' },
            'TCPLostRetransmit':                                                    { 'group': 'stats',  'name': 'lost_retransmit' },
            'timeouts after SACK recovery':                                         { 'group': 'stats',  'name': 'timeouts_after_sack_recovery' },
            'timeouts in loss state':                                               { 'group': 'stats',  'name': 'timeouts_in_loss_state', },
            'fast retransmits':                                                     { 'group': 'stats',  'name': 'fast_retransmits' },
            'forward retransmits':                                                  { 'group': 'stats',  'name': 'forward_retransmits' },
            'retransmits in slow start':                                            { 'group': 'stats',  'name': 'retransmits_in_slow_start' },
            'other TCP timeouts':                                                   { 'group': 'stats',  'name': 'other_timeouts' },
            'sack retransmits failed':                                              { 'group': 'stats',  'name': 'sack_retransmit_failed' },
            'packets collapsed in receive queue due to low socket buffer':          { 'group': 'stats',  'name': 'packets_collapsed_in_receive_queue_low_socket_buffer' },
            'TCPLossProbeRecovery':                                                 { 'group': 'stats',  'name': 'loss_probe_recovery' },
            'DSACKs sent for old packets':                                          { 'group': 'stats',  'name': 'dsacks_sent_for_old_packet' },
            'DSACKs sent for out of order packets':                                 { 'group': 'stats',  'name': 'dscaks_sent_for_out_of_order_packet' },
            'DSACKs received':                                                      { 'group': 'stats',  'name': 'dsacks_received' },
            'connections reset due to unexpected data':                             { 'group': 'stats',  'name': 'connection_reset_unexpected_data' },
            'connections reset due to early user close':                            { 'group': 'stats',  'name': 'connection_reset_early_user_close' },
            'connections aborted due to timeout':                                   { 'group': 'stats',  'name': 'connections_aborted_due_to_timeout' },
            'TCPDSACKIgnoredOld':                                                   { 'group': 'stats',  'name': 'dsack_ignored_old' },
            'TCPDSACKIgnoredNoUndo':                                                { 'group': 'stats',  'name': 'dsack_ignored_no_undo' },
            'TCPSackShifted':                                                       { 'group': 'stats',  'name': 'sack_shifted' },
            'TCPSackMerged':                                                        { 'group': 'stats',  'name': 'sack_merged' },
            'TCPBacklogDrop':                                                       { 'group': 'stats',  'name': 'sack_backlog_drop' },
            'TCPSpuriousRTOs':                                                      { 'group': 'stats',  'name': 'spurious_rtos' },
            'TCPSackShiftFallback':                                                 { 'group': 'stats',  'name': 'sack_shift_fallback' },
            'TCPRcvCoalesce':                                                       { 'group': 'stats',  'name': 'receive_coalesce' },
            'TCPOFOQueue':                                                          { 'group': 'stats',  'name': 'ofo_queue' },
            'TCPChallengeACK':                                                      { 'group': 'stats',  'name': 'challenge_ack' },
            'TCPSYNChallenge':                                                      { 'group': 'stats',  'name': 'syn_challenge' },
            'TCPAutoCorking':                                                       { 'group': 'stats',  'name': 'auto_corking' },
            'TCPOrigDataSent':                                                      { 'group': 'stats',  'name': 'original_data_sent' },

        },
    },

    'udp': {
        'counter_map': {
            'packets received':                     { 'group': 'stats', 'name': 'packets_received' },
            'packets sent':                         { 'group': 'stats', 'name': 'packets_sent' },
            'packets to unknown port received.':    { 'group': 'errors', 'name': 'packets_received_to_unknown port' },
            'packet receive errors':                { 'group': 'errors', 'name': 'packet_receive_errors' },
            'RcvbufErrors:':                        { 'group': 'errors', 'name': 'receive_buffer_errors' },
        },
    },

}

NETSTAT_PROTOCOL_COUNTERS_BSD = {

    'arp': {

        'counter_map': {
            'ARP requests sent':                                { 'group': 'sent', 'name': 'requests' },
            'ARP replies sent':                                 { 'group': 'sent', 'name': 'replies' },
            'ARP announcements sent':                           { 'group': 'sent', 'name': 'announcements' },
            'ARP conflict probes sent':                         { 'group': 'sent', 'name': 'conflict_probes'},
            'ARP requests received':                            { 'group': 'received', 'name': 'requests' },
            'ARP packets received':                             { 'group': 'received', 'name': 'packets' },
            'ARP replies received':                             { 'group': 'received', 'name': 'replies' },
            'invalid ARP resolve requests':                     { 'group': 'received', 'name': 'invalid_resolve_requests' },
            'total ARP packets received':                       { 'group': 'received', 'name': 'total' },
            'total packets dropped due to lack of memory':      { 'group': 'dropped', 'name': 'lack_of_memory' },
            'total packets dropped due to no ARP entry':        { 'group': 'dropped', 'name': 'no_arp_entry' },
            'total packets dropped during ARP entry removal':   { 'group': 'dropped', 'name': 'during_removal' },
            'ARP entrys timed out':                             { 'group': 'errors', 'name': 'timed_out' },
            'ARP entries timed out':                            { 'group': 'errors', 'name': 'timed_out' },
            'Duplicate IPs seen':                               { 'group': 'errors', 'name': 'duplicate_ip' },
        },

    },

    'icmp': {

        'counter_map': {
            'calls to icmp_error':                              { 'group': 'errors', 'name': 'calls_to_icmp_error' },
            'messages with bad code fields':                    { 'group': 'errors', 'name': 'bad_code_fields' },
            'bad checksums':                                    { 'group': 'errors', 'name': 'bad_checksum' },
            'message with bad length':                          { 'group': 'errors', 'name': 'bad_length' },
            'messages < minimum length':                        { 'group': 'errors', 'name': 'too_short_message' },
            'destination unreachable':                          { 'group': 'stats',  'name': 'destination_unreachable' },
            'echo':                                             { 'group': 'stats',  'name': 'echo' },
            'message responses generated':                      { 'group': 'stats',  'name': 'responses_generated' },
            'multicast echo requests ignored':                  { 'group': 'stats',  'name': 'multicast_echo_request_ignored' },
            'multicast timestamp requests ignored':             { 'group': 'stats',  'name': 'multicast_timestamp_request_ignored' },
            "errors not generated 'cuz old message was icmp":   { 'group': 'stats',  'name': 'error_not_generated_old_icmp' },
        },

        'histogram_map': {

            'Output histogram:': {
                'group': 'summary',
                'name': 'output',
                'counter_map': {
                    'echo reply':               { 'group': 'sent', 'name': 'echo_reply' },
                    'destination unreachable':  { 'group': 'sent', 'name': 'destination_unreachable' },
                }
            },

            'Input histogram:': {
                'group': 'summary',
                'name': 'input',
                'counter_map': {
                    'echo':                     { 'group': 'sent', 'name': 'echo' },
                    'destination unreachable':  { 'group': 'sent', 'name': 'destination_unreachable' },
                }
            },

        },
    },

    'icmp6': {

        'counter_map': {
            'calls to icmp_error': { 'group': 'errors', 'name': 'calls_to_icmp_error' },
        },

        'histogram_map': {

            'Output histogram:': {
                'group': 'summary',
                'name': 'output',
                'counter_map': {
                }
            },

            'Input histogram:': {
                'group': 'summary',
                'name': 'input',
                'counter_map': {
                }
            },

            'Histogram of error messages to be generated:': {
                'group': 'summary',
                'name': 'errors',
                'counter_map': {
                }
            },

        },

    },

    'igmp': {

        'counter_map': {
            'messages received':                                    { 'group': 'received',          'name': 'messages' },
            'membership reports received':                          { 'group': 'received',          'name': 'membership_reports' },
            'membership reports sent':                              { 'group': 'sent',              'name': 'membership_reports' },
            'messages received with too few bytes':                 { 'group': 'errors',            'name': 'messages_too_few_bytes' },
            'messages received with wrong TTL':                     { 'group': 'errors',            'name': 'messages_wrong_ttl' },
            'messages received with bad checksum':                  { 'group': 'errors',            'name': 'bad_checksum' },
            'membership reports received with invalid field(s)':    { 'group': 'errors',            'name': 'membership_reports_with_invalid_fields' },
            'V1/V2 membership queries received':                    { 'group': 'queries_received',  'name': 'v1_v2_membership' },
            'V3 membership queries received':                       { 'group': 'queries_received',  'name': 'v3_membership' },
            'general queries received':                             { 'group': 'queries_received',  'name': 'general' },
            'group queries received':                               { 'group': 'queries_received',  'name': 'group' },
            'group-source queries received':                        { 'group': 'queries_received',  'name': 'group_source' },
            'group-source queries dropped':                         { 'group': 'queries_dropped',   'name': 'group_source' },
        },

    },

    'ip': {

        'group_map': {

            'total packets received': {
                'name': 'packets_received',
                'counter_map': {
                    'bad header checksums':                         { 'group': 'headers',   'name': 'bad_checksums' },
                    'headers checksummed in software':              { 'group': 'headers',   'name': 'checksummed_in_software' },
                    'with size smaller than minimum':               { 'group': 'errors',    'name': 'too_small_size' },
                    'with data size < data length':                 { 'group': 'errors',    'name': 'data_size_less_than_data_length' },
                    'with data size > data length':                 { 'group': 'errors',    'name': 'data_size_more_than_data_length' },
                    'packets forced to software checksum':          { 'group': 'errors',    'name': 'packets_forced_to_sw_checksum' },
                    'packets for unknown/unsupported protocol':     { 'group': 'errors',    'name': 'packet_protocol_unsupported' },
                    'with ip length > max ip packet size':          { 'group': 'errors',    'name': 'ip_length_too_large' },
                    'with header length < data size':               { 'group': 'errors',    'name': 'header_length_more_than_data_size' },
                    'with data length < header length':             { 'group': 'errors',    'name': 'data_length_less_than_header_length' },
                    'with bad options':                             { 'group': 'errors',    'name': 'bad_options' },
                    'with incorrect version number':                { 'group': 'errors',    'name': 'incorrect_version_number' },
                    'packets received for unknown multicast group': { 'group': 'errors',    'name': 'received_for_unknown_multicast_group' },
                    'fragments received':                           { 'group': 'fragments', 'name': 'received' },
                    'reassembled ok':                               { 'group': 'fragments', 'name': 'reassembled_ok' },
                    'packets forwarded':                            { 'group': 'forward',   'name': 'packets_forwarded' },
                    'packets not forwardable':                      { 'group': 'forward',   'name': 'not_forwardable' },
                    'redirects sent':                               { 'group': 'redirect',  'name': 'redirects_sent' },
                    'dropped (dup or out of space)':                { 'group': 'dropped',   'name': 'dup_or_out_of_space' },
                    'dropped after timeout':                        { 'group': 'dropped',   'name': 'after_timeout' },

                }
            },

            'packets sent from this host': {
                'name': 'packets_sent',
                'counter_map': {
                    'packets sent with fabricated ip header':           { 'group': 'headers',   'name': 'fabricated_ip_header' },
                    'headers checksummed in software':                  { 'group': 'headers',   'name': 'checksummed_in_software' },
                    'output packets dropped due to no bufs, etc.':      { 'group': 'dropped',   'name': 'no_buffers_etc' },
                    'output packets discarded due to no route':         { 'group': 'dropped',   'name': 'no_route' },
                    'packets dropped due to no bufs for control data':  { 'group': 'dropped',   'name': 'no_bufs_for_control_data' },
                    'output datagrams fragmented':                      { 'group': 'fragments', 'name': 'output_packets' },
                    'fragments created':                                { 'group': 'fragments', 'name': 'created' },
                    "datagrams that can't be fragmented":               { 'group': 'fragments', 'name': 'datagrams_cant_be_fragmented' },
                    "tunneling packets that can't find gif":            { 'group': 'errors',    'name': 'tunneling_no_gif_found' },
                    'datagrams with bad address in header':             { 'group': 'errors',    'name': 'bad_address_in_header' },
                }
            },

        },
    },

    'ip6': {

        'histogram_map': {

            'Output histogram:': {
                'group': 'summary',
                'name': 'output',
                'counter_map': {
                }
            },

            'Input histogram:': {
                'group': 'summary',
                'name': 'input',
                'counter_map': {
                }
            },

            'Mbuf statistics:': {
                'group': 'stats',
                'name': 'mbuf',
                'counter_map': {
                }
            }
        },
    },

    'ipsec': {

        'counter_map': {
            'inbound packets processed successfully':               { 'group': 'inbound_packets', 'name': 'successfully_processed', },
            'inbound packets violated process security policy':     { 'group': 'inbound_packets', 'name': 'security_policy_violation', },
            'inbound packets with no SA available':                 { 'group': 'inbound_packets', 'name': 'no_sa', },
            'invalid inbound packets':                              { 'group': 'inbound_packets', 'name': 'invalid', },
            'inbound packets failed due to insufficient memory':    { 'group': 'inbound_packets', 'name': 'no_memory', },
            'inbound packets failed getting SPI':                   { 'group': 'inbound_packets', 'name': 'error_getting_spi', },
            'inbound packets failed on AH replay check':            { 'group': 'inbound_packets', 'name': 'ah_replay_check_fail', },
            'inbound packets failed on ESP replay check':           { 'group': 'inbound_packets', 'name': 'esp_reaply_check_fail', },
            'inbound packets considered authentic':                 { 'group': 'inbound_packets', 'name': 'authentic', },
            'inbound packets failed on authentication':             { 'group': 'inbound_packets', 'name': 'authentication_failure', },
            'outbound packets processed successfully':              { 'group': 'outbound_packets', 'name': 'successfully_processed', },
            'outbound packets violated process security policy':    { 'group': 'outbound_packets', 'name': 'security_policy_violation', },
            'outbound packets with no SA available':                { 'group': 'outbound_packets', 'name': 'no_sa', },
            'invalid outbound packets':                             { 'group': 'outbound_packets', 'name': 'invalid', },
            'outbound packets failed due to insufficient memory':   { 'group': 'outbound_packets', 'name': 'no_memory', },
            'outbound packets with no route':                       { 'group': 'outbound_packets', 'name': 'no_route', },
        },

        'histogram_map': {

            'ESP output histogram:': {
                'group': 'summary',
                'name': 'output',
                'counter_map': {
                }
            },

            'ESP input histogram:': {
                'group': 'summary',
                'name': 'input',
                'counter_map': {
                }
            },
        },
    },

    'ipsec6': {

        'counter_map': {
            'inbound packets processed successfully':               { 'group': 'inbound_packets', 'name': 'successfully_processed', },
            'inbound packets violated process security policy':     { 'group': 'inbound_packets', 'name': 'security_policy_violation', },
            'inbound packets with no SA available':                 { 'group': 'inbound_packets', 'name': 'no_sa', },
            'invalid inbound packets':                              { 'group': 'inbound_packets', 'name': 'invalid', },
            'inbound packets failed due to insufficient memory':    { 'group': 'inbound_packets', 'name': 'no_memory', },
            'inbound packets failed getting SPI':                   { 'group': 'inbound_packets', 'name': 'error_getting_spi', },
            'inbound packets failed on AH replay check':            { 'group': 'inbound_packets', 'name': 'ah_replay_check_fail', },
            'inbound packets failed on ESP replay check':           { 'group': 'inbound_packets', 'name': 'esp_reaply_check_fail', },
            'inbound packets considered authentic':                 { 'group': 'inbound_packets', 'name': 'authentic', },
            'inbound packets failed on authentication':             { 'group': 'inbound_packets', 'name': 'authentication_failure', },
            'outbound packets processed successfully':              { 'group': 'outbound_packets', 'name': 'successfully_processed', },
            'outbound packets violated process security policy':    { 'group': 'outbound_packets', 'name': 'security_policy_violation', },
            'outbound packets with no SA available':                { 'group': 'outbound_packets', 'name': 'no_sa', },
            'invalid outbound packets':                             { 'group': 'outbound_packets', 'name': 'invalid', },
            'outbound packets failed due to insufficient memory':   { 'group': 'outbound_packets', 'name': 'no_memory', },
            'outbound packets with no route':                       { 'group': 'outbound_packets', 'name': 'no_route', },
        },
    },

    'kctl': {

        'counter_map': {
            'total kernel control modules registered':      { 'group': 'kernel', 'name': 'total_control_modules_registered', },
            'current kernel control modules registered':    { 'group': 'kernel', 'name': 'current_control_modules_registered', },
            'current kernel control sockets':               { 'group': 'kernel', 'name': 'current_control_sockets' },
            'kernel control generation count':              { 'group': 'kernel', 'name': 'control_generations' },
            'connection attempts':                          { 'group': 'stats', 'name': 'connection_attempts' },
            'connection failures':                          { 'group': 'stats', 'name': 'connection_failures' },
            'send failures':                                { 'group': 'stats', 'name': 'send_failures' },
            'send list failures':                           { 'group': 'stats', 'name': 'send_list_failures' },
            'enqueus failures':                             { 'group': 'stats', 'name': 'enqueue_failures' },
            'packets dropped due to full socket buffers':   { 'group': 'dropped', 'name': 'full_socket_buffers' },
        },
    },

    'kevt': {

        'counter_map': {
            'current kernel control sockets':               { 'group': 'kernel', 'name': 'current_control_sockets' },
            'kernel control generation count':              { 'group': 'kernel', 'name': 'control_generation_count' },
            'message posteds':                              { 'group': 'kernel', 'name': 'messages_posted' },
            'bad vendor failures':                          { 'group': 'errors', 'name': 'bad_vendor' },
            'message too big failures':                     { 'group': 'errors', 'name': 'message_too_big' },
            'out of memeory failures':                      { 'group': 'errors', 'name': 'out_of_memory' },
            'messages dropped due to full socket buffers':  { 'group': 'errors', 'name': 'full_socket_buffers' },
        },
    },

    'mptcp': {

        'counter_map': {
            'data packets sent':                            { 'group': 'sent', 'name': 'packets' },
            'data bytes sent':                              { 'group': 'sent', 'name': 'bytes' },
            'data packets received':                        { 'group': 'received', 'name': 'packets' },
            'data bytes received':                          { 'group': 'received', 'name': 'bytes' },
            'subflow switches':                             { 'group': 'stats', 'name': 'subflow_switch' },
            'times the MPTCP subflow window was reduced':   { 'group': 'stats', 'name': 'subflow_window_reduce' },
            'packets with an invalid MPCAP option':         { 'group': 'errors', 'name': 'invalid_mpcap_option' },
            'packets with an invalid MPJOIN option':        { 'group': 'errors', 'name': 'invalid_mpjoin_option' },
            'times primary subflow fell back to TCP':       { 'group': 'errors', 'name': 'primary_subflow_tcp_fallback' },
            'times secondary subflow fell back to TCP':     { 'group': 'errors', 'name': 'secondary_subflow_tcp_fallback' },
            'DSS option drops':                             { 'group': 'errors', 'name': 'dss_option_drop' },
            'bad DSS checksums':                            { 'group': 'errors', 'name': 'bad_dss_checksum' },
            'times received out of order data':             { 'group': 'errors', 'name': 'out_of_order_data_received' },
            'other invalid MPTCP options':                  { 'group': 'errors', 'name': 'other_invalid_option_drop' },
        },
    },

    'pfkey': {

        'group_map': {

            'requests sent to userland': {
                'name': 'packets_sent',
                'counter_map': {
                    'bytes sent to userland':                       { 'group': 'sent', 'name': 'bytes_to_userland' },
                    'messages with invalid length field':           { 'group': 'errors', 'name': 'invalid_length' },
                    'messages with invalid version field':          { 'group': 'errors', 'name': 'invalid_version' },
                    'messages with invalid message type field':     { 'group': 'errors', 'name': 'invalid_message_type' },
                    'messages too short':                           { 'group': 'errors', 'name': 'too_short' },
                    'messages with memory allocation failure':      { 'group': 'errors', 'name': 'memory_allocation_fail' },
                    'messages with duplicate extension':            { 'group': 'errors', 'name': 'duplicate_extension' },
                    'messages with invalid extension type':         { 'group': 'errors', 'name': 'invalid_extension_type' },
                    'messages with invalid sa type':                { 'group': 'errors', 'name': 'invalid_sa_type' },
                    'messages with invalid address extension':      { 'group': 'errors', 'name': 'invalid_address_extension' },
                },
                'histogram_map': {
                    'histogram by message type:': {
                        'group': 'histogram',
                        'name': 'histogram_by_message_type',
                        'counter_map': {
                            'getspi':       { 'group': 'send', 'name': 'getspi' },
                            'update':       { 'group': 'send', 'name': 'update' },
                            'add':          { 'group': 'send', 'name': 'add' },
                            'delete':       { 'group': 'send', 'name': 'delete' },
                            'acquire':      { 'group': 'send', 'name': 'acquire' },
                            'register':     { 'group': 'send', 'name': 'register' },
                            'dump':         { 'group': 'send', 'name': 'dump' },
                            'x_spdadd':     { 'group': 'send', 'name': 'x_spdadd' },
                            'x_spddelete':  { 'group': 'send', 'name': 'x_spddelete' },
                            'x_spddump':    { 'group': 'send', 'name': 'x_spddump' },
                        },
                    },
                },
            },

            'requests sent from userland': {
                'name': 'packets_received',
                'counter_map': {
                    'bytes sent from userland':                     { 'group': 'sent', 'name': 'bytes_from_userland' },
                    'messages with memory allocation failure':      { 'group': 'errors', 'name': 'memory_allocationfailure' },
                    'messages toward single socket':                { 'group': 'sockets', 'name': 'to_single_socket' },
                    'messages toward all sockets':                  { 'group': 'sockets', 'name': 'to_all_sockets' },
                    'messages toward registered sockets':           { 'group': 'sockets', 'name': 'to_registered_sockets' },
                },
                'histogram_map': {
                    'histogram by message type:':                    {
                        'group': 'histogram',
                        'name': 'histogram_by_message_type',
                        'counter_map': {
                            'getspi':       { 'group': 'received', 'name': 'getspi' },
                            'update':       { 'group': 'received', 'name': 'update' },
                            'add':          { 'group': 'received', 'name': 'add' },
                            'expire':       { 'group': 'send', 'name': 'expire' },
                            'delete':       { 'group': 'received', 'name': 'delete' },
                            'acquire':      { 'group': 'received', 'name': 'acquire' },
                            'register':     { 'group': 'received', 'name': 'register' },
                            'dump':         { 'group': 'received', 'name': 'dump' },
                            'x_spdadd':     { 'group': 'received', 'name': 'x_spdadd' },
                            'x_spddelete':  { 'group': 'received', 'name': 'x_spddelete' },
                            'x_spddump':    { 'group': 'received', 'name': 'x_spddump' },
                        },
                    },
                },
            },

        },

    },

    'rip6': {
        'counter_map': {},
        'group_map': {},
        'histogram_map': {},
    },

    'sctp': {
        'counter_map': {
            "packet shorter than header":                                   { 'group': 'errors', 'name': 'packet_shorter_than_header' },
            "checksum error":                                               { 'group': 'errors', 'name': 'checksum_error' },
            "no endpoint for port":                                         { 'group': 'errors', 'name': 'no_endpoint_for_port' },
            "bad v-tag":                                                    { 'group': 'errors', 'name': 'bad_vtag' },
            "bad SID":                                                      { 'group': 'errors', 'name': 'bad_sid' },
            "no memory":                                                    { 'group': 'errors', 'name': 'no_memory' },
            "number of multiple FR in a RTT window":                        { 'group': 'stats', 'name': 'multiple_fr_in_rtt_window' },
            "RFC813 allowed sending":                                       { 'group': 'stats', 'name': 'rfc813_allowed_sending' },
            "RFC813 does not allow sending":                                { 'group': 'stats', 'name': 'rfc813_does_not_allow_sending' },
            "times max burst prohibited sending":                           { 'group': 'stats', 'name': 'max_burst_prohibited_sending' },
            "look ahead tells us no memory in interface":                   { 'group': 'stats', 'name': 'lookahead_no_memory_in_interface' },
            "numbers of window probes sent":                                { 'group': 'stats', 'name': 'window_probes_sent' },
            "times an output error to clamp down on next user send":        { 'group': 'stats', 'name': 'output_error_to_clamp_down_next_user_send' },
            "times sctp_senderrors were caused from a user":                { 'group': 'stats', 'name': 'sctp_senderrors_caused_from_user' },
            "number of in data drops due to chunk limit reached":           { 'group': 'stats', 'name': 'data_drops_due_to_chunk_limit' },
            "number of in data drops due to rwnd limit reached":            { 'group': 'stats', 'name': 'data_drops_due_to_rwnd_limit' },
            "times a ECN reduced the cwnd":                                 { 'group': 'stats', 'name': 'ecn_reduced_cwnd' },
            "used express lookup via vtag":                                 { 'group': 'stats', 'name': 'express_lookup_via_vtag' },
            "collision in express lookup":                                  { 'group': 'stats', 'name': 'collision_in_express_lookup' },
            "times the sender ran dry of user data on primary":             { 'group': 'stats', 'name': 'sender_ran_dry_of_user_data_on_primary' },
            "sacks the slow way":                                           { 'group': 'stats', 'name': 'slow_way_sacks' },
            "window update only sacks sent":                                { 'group': 'stats', 'name': 'window_update_only_sacks_sent' },
            "sends with sinfo_flags !=0":                                   { 'group': 'stats', 'name': 'sends_with_nonzero_sinfo_flags' },
            "unordered sends":                                              { 'group': 'stats', 'name': 'unordered_sends' },
            "sends with EOF flag set":                                      { 'group': 'stats', 'name': 'sends_with_eof_flag_set' },
            "sends with ABORT flag set":                                    { 'group': 'stats', 'name': 'sends_with_abort_flag_set' },
            "times protocol drain called":                                  { 'group': 'stats', 'name': 'protocol_drains_called' },
            "times we did a protocol drain":                                { 'group': 'stats', 'name': 'protocol_drains_done' },
            "times recv was called with peek":                              { 'group': 'stats', 'name': 'recv_called_with_peek' },
            "cached chunks used":                                           { 'group': 'stats', 'name': 'cached_chunks_used' },
            "cached stream oq's used":                                      { 'group': 'stats', 'name': 'cache_stream_oq_used' },
            "unread messages abandonded by close":                          { 'group': 'stats', 'name': 'unread_messages_abandoned_by_close' },
            "send burst avoidance, already max burst inflight to net":      { 'group': 'stats', 'name': 'send_burst_avoidance' },
            "send cwnd full avoidance, already max burst inflight to net":  { 'group': 'stats', 'name': 'send_cwnd_full_avoidance' },
            "number of map array over-runs via fwd-tsn's":                  { 'group': 'stats', 'name': 'map_array_overruns_via_fwd_tsn' },
        },
        'group_map': {
            'input packets': {
                'name': 'input_packets',
                'counter_map': {
                    'datagrams':                        { 'group': 'stats', 'name': 'datagrams' },
                    'packets that had data':            { 'group': 'stats', 'name': 'packets_with_data' },
                    'input SACK chunks':                { 'group': 'stats', 'name': 'input_sack_chunks' },
                    'input DATA chunks':                { 'group': 'stats', 'name': 'input_data_chunks' },
                    'duplicate DATA chunks':            { 'group': 'stats', 'name': 'duplicate_data_chunks' },
                    'input HB chunks':                  { 'group': 'stats', 'name': 'input_hb_chunks' },
                    'HB-ACK chunks':                    { 'group': 'stats', 'name': 'hb_ack_chunks' },
                    'input ECNE chunks':                { 'group': 'stats', 'name': 'input_ecne_chunks' },
                    'input AUTH chunks':                { 'group': 'stats', 'name': 'input_auth_chunks' },
                    'chunks missing AUTH':              { 'group': 'stats', 'name': 'chunks_without_auth' },
                    'invalid HMAC ids received':        { 'group': 'stats', 'name': 'invalid_hmac_ids_received' },
                    'invalid secret ids received':      { 'group': 'stats', 'name': 'invalid_secret_ids_received' },
                    'auth failed':                      { 'group': 'stats', 'name': 'auth_failed' },
                    'fast path receives all one chunk': { 'group': 'stats', 'name': 'fast_path_receives_all_one_chunk' },
                    'fast path multi-part data':        { 'group': 'stats', 'name': 'fast_path_multipart_data' },

                },
            },
            'output packets': {
                'name': 'output_packets',
                'counter_map': {
                    "output SACKs":                                     { 'group': 'stats', 'name': 'output_sacks', },
                    "output DATA chunks":                               { 'group': 'stats', 'name': 'output_data_chunks', },
                    "retransmitted DATA chunks":                        { 'group': 'stats', 'name': 'retransmitted_data_chunks', },
                    "fast retransmitted DATA chunks":                   { 'group': 'stats', 'name': 'fast_retransmitted_data_chunks', },
                    "FR's that happened more than once to same chunk":  { 'group': 'stats', 'name': 'fast_retransmits_more_than_once_to_same_chunk', },
                    "output HB chunks":                                 { 'group': 'stats', 'name': 'output_hb_chunks', },
                    "output ECNE chunks":                               { 'group': 'stats', 'name': 'output_ecne_chunks', },
                    "output AUTH chunks":                               { 'group': 'stats', 'name': 'output_auth_chunks', },
                    "ip_output error counter":                          { 'group': 'stats', 'name': 'ip_output_errors', },

                },
            },
        },
        'histogram_map': {
            'Packet drop statistics:': {
                'group': 'histogram',
                'name': 'packet_drop_statistics',
                'counter_map': {
                    "from middle box":                      { 'group': 'stats', 'name': 'from_middle_box' },
                    "from end host":                        { 'group': 'stats', 'name': 'from_end_box' },
                    "with data":                            { 'group': 'stats', 'name': 'with_data' },
                    "non-data, non-endhost":                { 'group': 'stats', 'name': 'non_data_non_endhost' },
                    "non-endhost, bandwidth rep only":      { 'group': 'stats', 'name': 'non_data_only_bandwidth_rep' },
                    "not enough for chunk header":          { 'group': 'stats', 'name': 'not_enough_for_chunk_header' },
                    "not enough data to confirm":           { 'group': 'stats', 'name': 'not_enough_data_to_confirm' },
                    "where process_chunk_drop said break":  { 'group': 'stats', 'name': 'where_process_chunk_stop_said_break' },
                    "failed to find TSN":                   { 'group': 'stats', 'name': 'failed_to_find_tsn' },
                    "attempt reverse TSN lookup":           { 'group': 'stats', 'name': 'attempt_reverse_tsn_lookup' },
                    "e-host confirms zero-rwnd":            { 'group': 'stats', 'name': 'ehost_confirm_zero_rewind' },
                    "midbox confirms no space":             { 'group': 'stats', 'name': 'midbox_confirm_no_space' },
                    "data did not match TSN":               { 'group': 'stats', 'name': 'data_did_not_match_tsn' },
                    "TSN's marked for Fast Retran":         { 'group': 'stats', 'name': 'tsn_makred_for_fast_retran' },
                },
            },
            'Timeouts:': {
                'group': 'histogram',
                'name': 'timeouts',
                'counter_map': {
                    'iterator timers fired':                { 'group': 'stats', 'name': 'iterator_timer_fired' },
                    'T3 data time outs':                    { 'group': 'stats', 'name': 't3_data_timeouts' },
                    'window probe (T3) timers fired':       { 'group': 'stats', 'name': 'window_probe_t3_timers_fired' },
                    'INIT timers fired':                    { 'group': 'stats', 'name': 'init_timer_fired' },
                    'sack timers fired':                    { 'group': 'stats', 'name': 'sack_timer_fired' },
                    'shutdown timers fired':                { 'group': 'stats', 'name': 'shutdown_timer_fired' },
                    'heartbeat timers fired':               { 'group': 'stats', 'name': 'heartbeat_timer_fired' },
                    'a cookie timeout fired':               { 'group': 'stats', 'name': 'cookie_timeout_fired' },
                    'an endpoint changed its cookiesecret': { 'group': 'stats', 'name': 'endpoint_changed_cookiesecret' },
                    'PMTU timers fired':                    { 'group': 'stats', 'name': 'pmtu_timer_fired' },
                    'shutdown ack timers fired':            { 'group': 'stats', 'name': 'shutdown_ack_timer_fired' },
                    'shutdown guard timers fired':          { 'group': 'stats', 'name': 'shutdown_guard_timer_fired' },
                    'stream reset timers fired':            { 'group': 'stats', 'name': 'stream_reset_timer_fired' },
                    'early FR timers fired':                { 'group': 'stats', 'name': 'early_fr_timer_fired' },
                    'an asconf timer fired':                { 'group': 'stats', 'name': 'asconf_timer_fired' },
                    'auto close timer fired':               { 'group': 'stats', 'name': 'auto_close_timer_fired' },
                    'asoc free timers expired':             { 'group': 'stats', 'name': 'asoc_free_timer_expired' },
                    'inp free timers expired':              { 'group': 'stats', 'name': 'inp_free_timer_expired' },
                },
            },
        },
    },

    'tcp': {

        'counter_map': {
            'connection requests':                              { 'group': 'received', 'name': 'connection_request', },
            'connection accepts':                               { 'group': 'received', 'name': 'connection_accept', },
            'SACK options (SACK blocks) received':              { 'group': 'received', 'name': 'sack_options' },
            'bad connection attempts':                          { 'group': 'errors', 'name': 'connection_attempt_bad', },
            'listen queue overflows':                           { 'group': 'errors', 'name': 'listen_queue_overflow', },
            'connections established (including accepts)':      { 'group': 'stats', 'name': 'established' },
            'segments updated rtt (of 1172312 attempts)':       { 'group': 'stats', 'name': 'segments_updated_rtt' },
            'correct ACK header predictions':                   { 'group': 'stats', 'name': 'correct_ack_header_predictions' },
            'correct data packet header predictions':           { 'group': 'stats', 'name': 'correct_data_packet_header_predictions' },
            'SACK recovery episodes':                           { 'group': 'stats', 'name': 'sack_recovery_episodes' },
            'SACK scoreboard overflow':                         { 'group': 'stats', 'name': 'sack_scoreboard_overflow' },
            'times cumulative ack advanced along with SACK':    { 'group': 'stats', 'name': 'cumulative_ack_advanced_with_sack' },
            'segment rexmits in SACK recovery episodes':        { 'group': 'stats', 'name': 'segment_rexmit_in_sack_recovery_episodes' },
            'byte rexmits in SACK recovery episodes':           { 'group': 'stats', 'name': 'byte_rexmit_in_sack_recovery_episodes' },
            'limited transmits done':                           { 'group': 'stats', 'name': 'limited_transmits' },
            'early retransmits done':                           { 'group': 'stats', 'name': 'early_transmits' },
            'SACK options (SACK blocks) sent':                  { 'group': 'sent',  'name': 'sack_options' },
            'embryonic connections dropped':                    { 'group': 'dropped', 'name': 'embryonic_connections' },
        },

        'group_map': {

            'packets sent': {
                'name': 'packets_sent',
                'counter_map': {
                    'data packets':                         { 'group': 'sent', 'name': 'packets' },
                    'data packets retransmitted':           { 'group': 'sent', 'name': 'packets_retransmitted' },
                    'resends initiated by MTU discovery':   { 'group': 'sent', 'name': 'resend_by_mtu_discovery' },
                    'ack-only packets':                     { 'group': 'sent', 'name': 'ack_only' },
                    'URG only packets':                     { 'group': 'sent', 'name': 'urg_only' },
                    'window probe packets':                 { 'group': 'sent', 'name': 'window_probe' },
                    'window update packets':                { 'group': 'sent', 'name': 'window_update' },
                    'control packets':                      { 'group': 'sent', 'name': 'control_packets' },
                    'data packets sent after flow control': { 'group': 'sent', 'name': 'data_packets_after_flow_control' },
                    'checksummed in software': {
                        'group': 'stats',
                        'name': 'checksummed_in_software',
                        'counter_map': {
                            'segments over IPv4': { 'group': 'segments', 'name': 'ipv4' },
                            'segments over IPv6': { 'group': 'segments', 'name': 'ipv6' },
                        }
                    },
                },
                'subgroups': (
                    'checksummed_in_software',
                ),
            },

            'packets received': {
                'name': 'packets_received',
                'counter_map': {
                    'acks':                                         { 'group': 'received',  'name': 'acks' },
                    'duplicate acks':                               { 'group': 'received',  'name': 'duplicate_acks' },
                    'acks for unsent data':                         { 'group': 'received',  'name': 'acks_for_unsent' },
                    'packets received in-sequence':                 { 'group': 'received',  'name': 'packets_in_sequence' },
                    'completely duplicate packets':                 { 'group': 'duplicate', 'name': 'completely_duplicate' },
                    'packets with some dup. data':                  { 'group': 'duplicate', 'name': 'some_duplicate_data' },
                    'old duplicate packets':                        { 'group': 'duplicate', 'name': 'old' },
                    'received packets dropped due to low memory':   { 'group': 'errors',    'name': 'low_memory' },
                    'out-of-order packets':                         { 'group': 'errors',    'name': 'out_of_order' },
                    'packets of data after window':                 { 'group': 'errors',    'name': 'data_after_window' },
                    'packets received after close':                 { 'group': 'errors',    'name': 'received_after_close' },
                    'bad resets':                                   { 'group': 'errors',    'name': 'bad_reset' },
                    'discarded for bad checksums':                  { 'group': 'discarded', 'name': 'bad_checksum_discarded' },
                    'discarded for bad header offset fields':       { 'group': 'discarded', 'name': 'bad_header_offset_fields' },
                    'discarded because packet too short':           { 'group': 'discarded', 'name': 'packet_too_short' },
                    'window probes':                                { 'group': 'stats',     'name': 'window_probes' },
                    'window update packets':                        { 'group': 'stats',     'name': 'window_update' },
                    'checksummed in software': {
                        'group': 'stats',
                        'name': 'checksummed_in_software',
                        'counter_map': {
                            'segments over IPv4': { 'group': 'segments', 'name': 'ipv4' },
                            'segments over IPv6': { 'group': 'segments', 'name': 'ipv6' },
                        }
                    },
                },
                'subgroups': (
                    'checksummed_in_software',
                ),
            },

            'retransmit timeouts': {
                'name': 'retransmit_timeouts',
                'counter_map': {
                    'connections dropped by rexmit timeout':        { 'group': 'dropped', 'name': 'after_retransmit_timeout' },
                    'connections dropped after retransmitting FIN': { 'group': 'dropped', 'name': 'after_fin_retransmit' },
                }
            },

            'keepalive timeouts': {
                'name':  'keepalive_timeouts',
                'counter_map': {
                    'keepalive probes sent':                    { 'group': 'sent',    'name': 'probes_sent' },
                    'connections dropped by keepalive':         { 'group': 'dropped', 'name': 'connections_dropped_by_keepalive' },
                }
            },

            'persist timeouts': {
                'name': 'persist_timeouts',
                'counter_map': {
                    'connections dropped by persist timeout':   { 'group': 'dropped', 'name': 'persist_timeout' },
                }
            },

            'LRO coalesced packets': {
                'name': 'lro_coalesced_packets',
                'counter_map': {
                    'collisions in LRO flow table':             { 'group': 'stats', 'name': 'lro_flow_table_collisions' },
                    'times LRO flow table was full':            { 'group': 'stats', 'name': 'lro_flow_table_full_count' },
                    'times LRO coalesced 2 packets':            { 'group': 'stats', 'name': 'lro_coalesce_2_count' },
                    'times LRO coalesced 3 or 4 packets':       { 'group': 'stats', 'name': 'lro_coalesce_3_4_count' },
                    'times LRO coalesced 5 or more packets':    { 'group': 'stats', 'name': 'lro_coalesce_5_count' },
                }
            },

            'connections negotiated ECN': {
                'name': 'ecn_negotiated_connections',
                'counter_map': {
                    'times congestion notification was sent using ECE': { 'group': 'stats', 'name': 'ece_cognestion_notifications' },
                    'times CWR was sent in response to ECE':            { 'group': 'stats', 'name': 'ece_response_with_cwr' },
                }
            },

            'times packet reordering was detected on a connection': {
                'name': 'packet_reordering_detected',
                'counter_map': {
                    'times transmitted packets were reordered':                 { 'group': 'stats', 'name': 'transmitted_packets_reordered' },
                    'times fast recovery was delayed to handle reordering':     { 'group': 'stats', 'name': 'fast_recovery_delayed' },
                    'times retransmission was avoided by delaying recovery':    { 'group': 'stats', 'name': 'delaying_recovery_avoided_retransmission' },
                    'retransmissions not needed':                               { 'group': 'stats', 'name': 'not_needed' },
                }
            },

        },

    },

    'udp': {
        'counter_map': {},
        'group_map': {

            'datagrams received': {
                'name': 'datagrams_received',
                'counter_map': {
                    'delivered':                                    { 'group': 'stats', 'name': 'delivered' },
                    'times multicast source filter matched':        { 'group': 'stats', 'name': 'multicast_filter_match' },
                    'with incomplete header':                       { 'group': 'stats', 'name': 'incomplete_header' },
                    'with bad data length field':                   { 'group': 'stats', 'name': 'bad_data_length_field' },
                    'with bad checksum':                            { 'group': 'stats', 'name': 'bad_checksum' },
                    'with no checksum':                             { 'group': 'stats', 'name': 'no_checksum' },
                    'not for hashed pcb':                           { 'group': 'stats', 'name': 'not_hashed_pcb' },
                    'broadcast/multicast datagrams undelivered':    { 'group': 'stats', 'name': 'undelivered_broadcast_multicast' },
                    'dropped due to no socket':                     { 'group': 'dropped', 'name': 'no_socket' },
                    'dropped due to full socket buffers':           { 'group': 'dropped', 'name': 'socket_buffers_full' },
                    'checksummed in software': {
                        'group': 'stats',
                        'name': 'checksummed_in_software',
                        'counter_map': {
                            'datagrams over IPv4': { 'group': 'checksummed_datagrams', 'name': 'ipv4' },
                            'datagrams over IPv6': { 'group': 'checksummed_datagrams', 'name': 'ipv6' },
                        }
                    },
                },
                'subgroups': (
                    'checksummed_in_software',
                ),
            },

            'datagrams output': {
                'name': 'datagrams_sent',
                'counter_map': {
                    'checksummed in software': {
                        'group': 'stats',
                        'name': 'checksummed_in_software',
                        'counter_map': {
                            'datagrams over IPv4': { 'group': 'checksummed_datagrams', 'name': 'ipv4' },
                            'datagrams over IPv6': { 'group': 'checksummed_datagrams', 'name': 'ipv6' },
                        }
                    },
                },
                'subgroups': (
                    'checksummed_in_software',
                ),
            },

        },
        'histogram_map': {},
    },

}


class NetstatStatisticsError(Exception):
    pass


class Counter(object):
    """Netstat counter

    Instance of output couunter
    """
    def __init__(self, protocol, parent, group, name, value=None, counter_map={}):
        self.protocol = protocol
        self.parent = parent
        self.group = group
        self.name = name.rstrip(':')
        self.details = {}

        if value is not None:
            self.value = int(value)
        else:
            self.value = value

        self.counter_map = counter_map
        self.counters = []

    @property
    def path(self):
        """Path to counter

        Dot separated path to counter
        """
        return '.'.join([self.parent.path, self.group, self.name])

    def __repr__(self):
        return self.path

    def __cmp__(self, other):
        for key in ('protocol', 'group', 'name', ):
            a = getattr(self, key)
            b = getattr(other, key)
            if a != b:
                return cmp(a, b)
        return 0

    def add_counter(self, name, value):
        try:
            config = self.counter_map[name]
            counter = Counter(self.protocol, self, config['group'], config['name'], value, counter_map=config.get('counter_map', {}))
            self.counters.append(counter)
            return counter

        except KeyError:
            return None

    def as_dict(self):
        data = {
            'name': self.name,
            'path': self.path,
            'value': self.value,
        }

        if self.details:
            data['details'] = self.details

        if self.counters:
            data['counters'] = [counter.as_dict() for counter in self.counters]

        return data


class Group(Counter):
    """Group of counters

    More detailed counters grouped under a higher level counter value.
    """
    def __init__(self, protocol, name, value, counter_map, subgroups, histogram_map):
        Counter.__init__(self, protocol, protocol, name, name, value, counter_map)

        self.subgroups = subgroups

        self.histogram_map = histogram_map
        self.histograms = []

        self.current_histogram = None
        self.current_subgroup = None

    @property
    def path(self):
        return '.'.join([self.protocol.path, self.name])

    def __repr__(self):
        return '%s.%s group %s value %s' % (self.protocol.name, self.group, self.name, self.value)

    def set_histogram(self, name):
        try:
            details = self.histogram_map[name]
        except KeyError:
            raise NetstatStatisticsError('Invalid %s histogram: %s' % (self.name, name))

        histogram = Histogram(self, self, details['group'], details['name'], counter_map=details['counter_map'])
        self.histograms.append(histogram)
        self.current_histogram = histogram
        return histogram

    def add_counter(self, name, value):
        if self.current_subgroup:
            counter = self.current_subgroup.add_counter(name, value)
            if counter is not None:
                return counter
            else:
                self.current_subgroup = None
                self.current_histogram = None

        counter = Counter.add_counter(self, name, value)

        if counter is not None:
            if counter.name in self.subgroups:
                self.current_subgroup = counter
                self.current_histogram = None

        elif self.current_histogram is not None:
            self.current_histogram.add_counter(name, value)

        return counter

    def as_dict(self):
        data = Counter.as_dict(self)
        if self.histograms:
            data['histograms'] = [histogram.as_dict() for histogram in self.histograms]
        return data


class Histogram(Counter):
    """Histogram group

    Group of counter where the group has no counter, just title.
    """
    def __init__(self, protocol, parent, group, name, counter_map):
        Counter.__init__(self, protocol, parent, group, name, counter_map=counter_map)

    def __repr__(self):
        return '%s.%s %s %s' % (self.protocol.name, self.group, self.name)

    def add_counter(self, name, value):
        counter = Counter.add_counter(self, name, value)

        if counter is not None:
            return counter


class Protocol(dict):
    """Protocol

    Protocol reported by netstat -s, with lowercase name
    """
    def __init__(self, name, counter_map=None, group_map=None, histogram_map=None):
        self.name = name
        self.counter_map = counter_map
        self.group_map = group_map
        self.histogram_map = histogram_map

        self.groups = []
        self.histograms = []

        self.current_group = None
        self.current_histogram = None

    def __repr__(self):
        return self.name

    def __cmp__(self, other):
        return cmp(self.name, other.name)

    @property
    def path(self):
        return self.name

    @property
    def all_counters(self):
        counters = []
        counters.extend(counter for group in self.values() for counter in group)

        for histogram in self.histograms:
            counters.extend(counter for counter in histogram.counters)

        for group in self.groups:
            for counter in group.counters:
                counters.append(counter)
                counters.extend(counter for counter in counter.counters)

            for histogram in group.histograms:
                counters.extend(counter for counter in histogram.counters)

        return counters

    def keys(self):
        return [key for key in sorted(dict.keys(self))]

    def items(self):
        return [(key, self[key]) for key in self.keys()]

    def values(self):
        return [self[key] for key in self.keys()]

    def clear(self):
        self.counters = []
        self.groups = []
        self.histograms = []
        self.current_group = None
        self.current_histogram = None

    def set_group(self, name, value):
        try:
            details = self.group_map[name]
        except KeyError:
            raise NetstatStatisticsError('Invalid %s group: %s' % (self.name, name))

        group = Group(
            self,
            details['name'],
            value,
            details['counter_map'],
            details.get('subgroups', {}),
            details.get('histogram_map', {}),
        )
        self.groups.append(group)
        self.current_group = group
        return group

    def set_histogram(self, name):
        try:
            details = self.histogram_map[name]
        except KeyError:
            raise NetstatStatisticsError('Invalid %s histogram: %s' % (self.name, name))

        histogram = Histogram(
            self,
            self,
            details['group'],
            details['name'],
            counter_map=details['counter_map']
        )
        self.histograms.append(histogram)
        self.current_histogram = histogram
        return histogram

    def set_direct_counter(self, name, value, counter_map):
        try:
            details = self.counter_map[name]
            counter = Counter(self, self, details['group'], details['name'], value, counter_map=counter_map)
            self.current_group = None
            self.current_histogram = None
            return counter

        except KeyError:
            return None

    def add_counter(self, counter):
        if counter.group not in self:
            self[counter.group] = []
        self[counter.group].append(counter)

    def add(self, line):
        def split_details(data):
            config = {
                'name': data['name'],
                'value': data['value'],
            }
            if 'name_continued' in data:
                config['name'] += ' %s' % data['name_continued']

            details = {}
            for key in data.keys():
                if key not in ('name', 'name_continued', 'value', ):
                    details[key] = data[key]

            return config, details

        def parse_counter(name, value, counter_map={}):
            if self.current_group is not None:
                counter = self.current_group.add_counter(name, value)
                if counter:
                    return counter

            if self.current_histogram is not None:
                counter = self.current_histogram.add_counter(name, value)
                if counter:
                    return counter

            if self.counter_map is not None:
                counter = self.set_direct_counter(name, value, counter_map)
                if counter is not None:
                    self.add_counter(counter)
                    return counter

            if self.group_map is not None and name in self.group_map:
                counter = self.set_group(name, value)
                return counter

            if self.histogram_map is not None and name in self.histogram_map:
                return self.set_histogram(name, value)

            return Counter(self, self, None, name, value, counter_map)

        line = line.strip()
        counter = None
        for regexp in COUNTER_REGEXPS:
            m = regexp.match(line)
            if not m:
                continue
            config, details = split_details(m.groupdict())
            counter = parse_counter(**config)
            break

        if counter is not None:
            return counter

        elif self.histogram_map is not None and line in self.histogram_map:
            return self.set_histogram(line)

        elif self.current_group is not None:
            if line in self.current_group.histogram_map:
                self.current_group.set_histogram(line)


    def as_dict(self):
        data = {
            'name': self.name,
            'counters': {}
        }

        for group in self.keys():
            data['counters'][group] = [counter.as_dict() for counter in self[group]]

        for attr in ( 'groups', 'histograms', ):
            if not getattr(self, attr):
                continue
            data[attr] = [entry.as_dict() for entry in getattr(self, attr)]

        return data


class NetstatStatistics(dict):
    """Parse netstat -s output

    Parser for netstat -s output. Contains Group, Histogram and Counter objects.
    """
    def __init__(self):
        if sys.platform in ( 'linux2', ):
            self.__lineparser_dict__ = NETSTAT_PROTOCOL_COUNTERS_LINUX

        elif fnmatch.fnmatch(sys.platform, '*bsd*') or sys.platform in ( 'darwin', ):
            self.__lineparser_dict__ = NETSTAT_PROTOCOL_COUNTERS_BSD

        else:
            raise NotImplementedError('Support for %s not yet implemented.' % sys.platform)

        for name in sorted(self.__lineparser_dict__.keys()):
            self[name] = Protocol(name, **self.__lineparser_dict__[name])
        self.updated = datetime.now()

    @property
    def protocols(self):
        return self.values()

    @property
    def all_counters(self):
        counters = []

        for protocol in self.values():
            counters.extend(protocol.all_counters)

        return counters

    @property
    def delta(self):
        ns = NetstatStatistics()
        ns.load()

        counters = []
        for counter in self.all_counters:
            new = ns.find_by_path(counter.path)
            if not new:
                continue
            if counter.value != new.value:
                counters.append(new)

        return ns, counters

    def load(self, protocols=[]):
        p = Popen(['netstat', '-s'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

        for protocol in self.protocols:
            protocol.clear()

        protocol = None
        for line in [line.rstrip() for line in stdout.splitlines()]:
            if RE_PROTOCOL.match(line):
                try:
                    protocol = self[line.lower().rstrip(':')]
                except KeyError:
                    continue

            elif protocol is not None:
                if not protocols or protocol.name in protocols:
                    counter = protocol.add(line)

    def find_by_path(self, path):
        for counter in self.all_counters:
            if counter.path == path:
                return counter
        return None


    def as_dict(self):
        return {
            'host': os.uname()[1],
            'platform': sys.platform,
            'updated': self.updated.strftime(DATE_FORMAT),
            'protocols': [protocol.as_dict() for protocol in self.protocols]
        }


def counter_match_pattern(counter, pattern):
    """Match pattern to counter path

    Returns True if given counter matches the pattern provided. Patterns can be simple
    strings or dot separated path patterns (for example tcp.sent.*).
    """
    if not isinstance(counter, Counter):
        raise NetstatStatisticsError('Not a Counter instance: %s' % counter)

    pattern_parts = [part for part in pattern.split('.') if part != '']
    counter_parts = counter.path.split('.')

    if len(pattern_parts) == 1:
        if fnmatch.fnmatch(counter.path, pattern):
            return True

    for i, match in enumerate(pattern_parts):
        if not fnmatch.fnmatch(counter_parts[i], match):
            return False

    return True


def filter_counters(counters, patterns, negate=False):
    """Filter counters by patterns

    Filters counters with counter_match_pattern matching any of patterns provided.

    If negate is True, patterns NOT matching any of patterns are returned.
    """
    if isinstance(patterns, basestring):
        patterns = patterns.split(',')

    if not patterns:
        return counters

    matched = []
    for pattern in patterns:
        for counter in counters:
            if counter_match_pattern(counter, pattern):
                if not negate:
                    matched.append(counter)
            else:
                if negate:
                    matched.append(counter)

    return matched

