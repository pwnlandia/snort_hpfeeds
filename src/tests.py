import unittest
import json

from snort import Alert
class TestSnortParser(unittest.TestCase):
    maxDiff = None
    
    def test_parse_buffer_udp(self):
        buf = """[**] [1:2003195:5] ET POLICY Unusual number of DNS No Such Name Responses [**]
[Classification: Potentially Bad Traffic] [Priority: 2] 
05/04/14-11:49:27.431227 3.3.3.3:53 -> 1.1.1.1:50649
UDP TTL:40 TOS:0x0 ID:3969 IpLen:20 DgmLen:133
Len: 105
[Xref => http://doc.emergingthreats.net/2003195]"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "1.1.1.1", "date": "2014-05-04T11:49:27.431227", "classification": "Potentially Bad Traffic", "proto": "UDP", "source_ip": "3.3.3.3", "priority": "2", "header": "1:2003195:5", "signature": "ET POLICY Unusual number of DNS No Such Name Responses", "source_port": "53", "destination_port": "50649", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

    def test_parse_buffer_icmp(self):
        buf = """[**] [1:486:4] ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited [**]
[Classification: Misc activity] [Priority: 3] 
05/04/14-11:30:01.347127 2.2.2.2 -> 1.1.1.1
ICMP TTL:51 TOS:0x0 ID:63425 IpLen:20 DgmLen:68
Type:3  Code:10  DESTINATION UNREACHABLE: ADMINISTRATIVELY PROHIBITED HOST FILTERED
** ORIGINAL DATAGRAM DUMP:
1.1.1.1:110 -> 2.2.2.2:46722
TCP TTL:49 TOS:0x0 ID:0 IpLen:20 DgmLen:40 DF
Seq: 0x0
(12 more bytes of original packet)
** END OF DUMP"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "1.1.1.1", "classification": "Misc activity", "proto": "ICMP", "source_ip": "2.2.2.2", "priority": "3", "header": "1:486:4", "signature": "ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited", "date": "2014-05-04T11:30:01.347127", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

    def test_parse_buffer_tcp(self):
        buf = """[**] [1:99999:1] test test [**]
[Priority: 0] 
07/18/14-18:37:36.311624 10.254.254.1:58132 -> 10.254.254.100:22
TCP TTL:255 TOS:0x0 ID:12300 IpLen:20 DgmLen:52 DF
***A**** Seq: 0xC468E7DA  Ack: 0x98D42D0C  Win: 0x202B  TcpLen: 32
TCP Options (3) => NOP NOP TS: 669698286 1044016 
"""
        alert = json.loads(Alert.parse_buffer("12345", buf).to_json())
        expected = json.loads('''{"destination_ip": "10.254.254.100", "destination_port": "22", "classification": "", "proto": "TCP", "source_ip": "10.254.254.1", "source_port": "58132", "priority": "0", "header": "1:99999:1", "signature": "test test", "date": "2014-07-18T18:37:36.311624", "sensor": "12345"}''')
        self.assertEqual(expected, alert)

if __name__ == '__main__':
    unittest.main()
