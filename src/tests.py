import unittest
import json

from snort import Alert
class TestSnortParser(unittest.TestCase):
    maxDiff = None
    
    def test_parse_buffer_udp(self):
        buf = """[**] [1:2003195:5] ET POLICY Unusual number of DNS No Such Name Responses [**]
[Classification: Potentially Bad Traffic] [Priority: 2] 
05/04-07:49:27.431227 3.3.3.3:53 -> 1.1.1.1:50649
UDP TTL:40 TOS:0x0 ID:3969 IpLen:20 DgmLen:133
Len: 105
[Xref => http://doc.emergingthreats.net/2003195]"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "1.1.1.1", "date": "2014-05-04T11:49:27.431226", "classification": "Potentially Bad Traffic", "proto": "UDP", "source_ip": "3.3.3.3", "priority": "2", "header": "1:2003195:5", "signature": "ET POLICY Unusual number of DNS No Such Name Responses", "source_port": "53", "destination_port": "50649", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

    def test_parse_buffer_icmp(self):
        buf = """[**] [1:486:4] ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited [**]
[Classification: Misc activity] [Priority: 3] 
05/04-07:30:01.347127 2.2.2.2 -> 1.1.1.1
ICMP TTL:51 TOS:0x0 ID:63425 IpLen:20 DgmLen:68
Type:3  Code:10  DESTINATION UNREACHABLE: ADMINISTRATIVELY PROHIBITED HOST FILTERED
** ORIGINAL DATAGRAM DUMP:
1.1.1.1:110 -> 2.2.2.2:46722
TCP TTL:49 TOS:0x0 ID:0 IpLen:20 DgmLen:40 DF
Seq: 0x0
(12 more bytes of original packet)
** END OF DUMP"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "1.1.1.1", "classification": "Misc activity", "proto": "ICMP", "source_ip": "2.2.2.2", "priority": "3", "header": "1:486:4", "signature": "ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited", "date": "2014-05-04T11:30:01.347126", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

    def test_parse_buffer_tcp(self):
        buf = """[**] [1:486:4] ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited [**]
[Classification: Misc activity] [Priority: 3] 
05/04-07:30:01.336466 2.2.2.2 -> 1.1.1.1
ICMP TTL:51 TOS:0x0 ID:63424 IpLen:20 DgmLen:68
Type:3  Code:10  DESTINATION UNREACHABLE: ADMINISTRATIVELY PROHIBITED HOST FILTERED
** ORIGINAL DATAGRAM DUMP:
1.1.1.1:110 -> 2.2.2.2:46723
TCP TTL:49 TOS:0x0 ID:0 IpLen:20 DgmLen:40 DF
Seq: 0x0
(12 more bytes of original packet)
** END OF DUMP
"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "1.1.1.1", "classification": "Misc activity", "proto": "ICMP", "source_ip": "2.2.2.2", "priority": "3", "header": "1:486:4", "signature": "ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited", "date": "2014-05-04T11:30:01.336465", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

if __name__ == '__main__':
    unittest.main()
