#!/usr/bin/env python3
"""Construct tiny captures to verify protocol sums and measurement flags."""
import hashlib
import struct
import tempfile
import time
from pathlib import Path
import extract_metrics as em


ETH = bytes.fromhex("00112233445566778899aabb")
def ipv4(fragment=0, payload=b"\x00\x35\x12\x34\x00\x08\x00\x00"):
    n=20+len(payload)
    return struct.pack("!BBHHHBBH4s4s",0x45,0,n,1,fragment,64,17,0,bytes([192,0,2,1]),bytes([192,0,2,2]))+payload

def ipv6():
    # Eight-byte hop-by-hop extension followed by an eight-byte UDP datagram.
    ext=b"\x11\x00"+b"\x00"*6; udp=b"\x00\x35\x12\x34\x00\x08\x00\x00"
    return struct.pack("!IHBB16s16s",6<<28,len(ext)+len(udp),0,64,b"\x20\x01"+b"\x00"*14,b"\x20\x02"+b"\x00"*14)+ext+udp

def ether(payload, kind): return ETH + struct.pack("!H",kind) + payload

def pcap(records):
    out=struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1)
    for sec,usec,frame,original_len in records:
        out+=struct.pack("<IIII",sec,usec,len(frame),original_len)+frame
    return out

def block(kind, body):
    n=12+len(body)
    assert n%4==0
    return struct.pack("<II",kind,n)+body+struct.pack("<I",n)

def pcapng(records):
    out=block(0x0a0d0d0a,struct.pack("<IHHq",0x1a2b3c4d,1,0,-1))
    # Two Ethernet interfaces, both default microsecond precision.
    for _ in range(2): out+=block(1,struct.pack("<HHI",1,0,65535))
    for interface,ticks,frame in records:
        padding=b"\x00"*((-len(frame))%4)
        out+=block(6,struct.pack("<IIIII",interface,ticks>>32,ticks&0xffffffff,len(frame),len(frame))+frame+padding)
    return out

def check(name, contents, expected):
    with tempfile.TemporaryDirectory() as tmp:
        em.BASELINE=tmp
        f=Path(tmp)/"undefended"/"fixture.example"/name
        f.parent.mkdir(parents=True)
        f.write_bytes(contents)
        row=dict(defense="undefended",domain="fixture.example",session="1",filename=name,drive_file_id="test",
                 size=str(len(contents)),sha256=hashlib.sha256(contents).hexdigest())
        out=em.measure(row,"http://127.0.0.1:1",1)
        assert out["status"]=="ok",out
        for key,value in expected.items():
            assert out[key]==value,(key,out[key],value,out)

def main():
    a=ether(ipv4(),0x0800);b=ether(ipv6(),0x86dd)
    check("test.pcap",pcap([(100,0,a,len(a)),(101,500000,b,len(b))]),
          dict(packet_count=2,packet_bytes=len(a)+len(b),ip_bytes=28+56,ipv4_packets=1,ipv6_packets=1,
               truncated_packets=0,non_ip_packets=0,multiple_ip_packets=0,span_seconds=1.5,ip_valid=True))
    check("test.pcapng",pcapng([(0,100000000,a),(1,102500000,b)]),
          dict(packet_count=2,packet_bytes=len(a)+len(b),ip_bytes=28+56,ipv4_packets=1,ipv6_packets=1,
               span_seconds=2.5,ip_valid=True))
    fragment=ether(ipv4(fragment=0x2000),0x0800)
    check("fragment.pcap",pcap([(100,0,fragment,len(fragment))]),
          dict(packet_count=1,ip_bytes=28,ipv4_packets=1,ip_valid=True))
    check("truncated.pcap",pcap([(100,0,a[:34],len(a))]),dict(packet_count=1,truncated_packets=1,ip_valid=False))
    arp=ether(b"\x00"*28,0x0806)
    check("nonip.pcap",pcap([(100,0,arp,len(arp))]),dict(packet_count=1,non_ip_packets=1,ip_valid=False))
    inner=ipv4(); outer=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(inner),1,0,64,4,0,bytes([192,0,2,1]),bytes([192,0,2,2]))+inner
    tunnel=ether(outer,0x0800)
    check("tunnel.pcap",pcap([(100,0,tunnel,len(tunnel))]),dict(packet_count=1,multiple_ip_packets=1,ip_valid=False))
    badip=bytearray(ipv4());badip[2:4]=struct.pack("!H",200)
    malformed=ether(bytes(badip),0x0800)
    check("malformed.pcap",pcap([(100,0,malformed,len(malformed))]),
          dict(packet_count=1,malformed_ip_packets=1,ip_valid=False))
    up=ether(ipv4(payload=struct.pack("!HHHH",1234,443,8,0)),0x0800)
    downip=bytearray(ipv4(payload=struct.pack("!HHHH",443,1234,8,0)))
    downip[12:16],downip[16:20]=downip[16:20],downip[12:16]
    down=ether(bytes(downip),0x0800)
    check("direction.pcap",pcap([(100,0,up,len(up)),(101,0,down,len(down))]),
          dict(packet_count=2,ip_bytes=56,udp443_tuple_candidates=1,udp443_direction_valid=True,
               udp443_up_ip_bytes=28,udp443_down_ip_bytes=28,other_ip_bytes=0))
    up2=ether(ipv4(payload=struct.pack("!HHHH",1235,443,8,0)),0x0800)
    check("ambiguous.pcap",pcap([(100,0,up,len(up)),(101,0,down,len(down)),(102,0,up2,len(up2))]),
          dict(packet_count=3,udp443_tuple_candidates=2,udp443_direction_valid=False,udp443_up_ip_bytes=None))
    with tempfile.TemporaryDirectory() as tmp:
        em.BASELINE=tmp
        sample=Path(tmp)/"undefended"/"fixture.example"/"test.pcap"
        sample.parent.mkdir(parents=True)
        sample.write_bytes(pcap([(100,0,a,len(a))]))
        row=dict(defense="undefended",domain="fixture.example",session="1",filename="test.pcap",drive_file_id="test",
                 size=str(sample.stat().st_size),sha256=hashlib.sha256(sample.read_bytes()).hexdigest())
        old_cap,old_shark=em.CAPINFOS,em.TSHARK
        try:
            cap=Path(tmp)/"fakecap";shark=Path(tmp)/"fakeshark"
            cap.write_text('#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nsys.stderr.write("x"*200000)\nprint("\\\"/dev/stdin\\\"\\t\\\"pcap\\\"\\t\\\"ether\\\"\\t\\\"1\\\"\\t\\\"42\\\"\\t\\\"0\\\"\\t\\\"100\\\"\\t\\\"100\\\"\\t\\\"True\\\"")\n')
            shark.write_text('#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nsys.stderr.write("y"*200000)\nprint("42\\t42\\t28\\t\\t0x0800\\t\\t20\\t192.0.2.1\\t192.0.2.2\\t\\t\\t53\\t1234")\n')
            cap.chmod(0o700);shark.chmod(0o700)
            em.CAPINFOS=str(cap);em.TSHARK=str(shark)
            out=em.measure(row,"http://127.0.0.1:1",4)
            assert out["status"]=="ok",out
            shark.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(15)\n')
            start=time.monotonic()
            out=em.measure(row,"http://127.0.0.1:1",1)
            assert out["status"]=="error" and "TimeoutError" in out["error"] and time.monotonic()-start<4,out
        finally:
            em.CAPINFOS=old_cap;em.TSHARK=old_shark
    print("9 packet fixtures, stderr-drain and child-timeout tests passed")

if __name__=="__main__":main()
