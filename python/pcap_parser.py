#!/usr/bin/env python
# coding: utf-8

import binascii
import os
from datetime import datetime
# In[243]:


# 타이틀 출력 포맷
TITLE_PRINT_FORMAT = "{0:#^100}"


# In[244]:


# BinaryFile Class
class BinaryFile:
    path = None
    file_size = None
    bytes_array = None
    
    def __init__(self, path):
        string = None
        self.path = path
        self.file_size = os.stat(path).st_size * 0.001
        
        with open(path, 'rb') as f:
            string = f.read()
            
        self.bytes_array = string
        
    def make_hex_sep(string):
        new_string = ""
        cnt = 0
        hex_cnt = 0

        for s in string:
            cnt = cnt + 1

            new_string = new_string + s

            if(cnt == 2):
                new_string = new_string + " "
                cnt = 0

        return new_string
    
    def print_info(self):
        path_str = "file path : {}".format(self.path)
        size_str = "file size : {}KB".format(self.file_size)
        title_str = TITLE_PRINT_FORMAT.format(" FILE INFO ")
        
        print(title_str)
        print("#{}#".format(path_str.center(len(title_str)-2)))
        print("#{}#".format(size_str.center(len(title_str)-2)))
        print("#" * len(title_str))
        
    def get_bytes_array(self):
        return self.bytes_array, len(self.bytes_array)


# In[245]:


# Pcap Global Header Class
class PcapGlobalHeader:
    # Pcap Global Header의 총 byte 길이
    BYTE_LENGTH = 24
    # 데이터 링크 사전
    DATA_LINK = {0:'NULL', 1:'Ethernet', 3:'AX254'}
    
    magic_number  = None  # 매직넘버
    pcap_version  = None  # pcap 버전
    this_zone     = None  # time_zone
    sigfigs       = None   # ? (항상 0임)
    snaplen       = None   # 버퍼의 크기
    network_adapter = None # link layer의 타입
    
    # bytes array를 입력하여 정보를 추출하는 메소드
    def get_info_from_bytes(self, bytes_arr):
        # 필요한 bytes 만 얻음
        header_arr = bytes_arr[:self.BYTE_LENGTH]
        
        # magic number 얻기 (4byte)
        self.magic_number = int.from_bytes(header_arr[0:4],byteorder='little')
        # pcap 메이저 버전 (2byte)
        version_major = int.from_bytes(header_arr[4:6],byteorder='little')
        # pcap 마이너 버전 (2byte)
        version_minor = int.from_bytes(header_arr[6:8],byteorder='little')
        # this zone (4byte)
        self.this_znoe = int.from_bytes(header_arr[8:12],byteorder='little')
        # sigfigs (4byte)
        self.sigfigs = int.from_bytes(header_arr[12:16],byteorder='little')
        # snaplen (4byte)
        self.snaplen = int.from_bytes(header_arr[16:20],byteorder='little')
        # 네트워크 어뎁터 (4byte)
        self.network_adapter = int.from_bytes(header_arr[20:24],byteorder='little')
        self.network_adapter = self.DATA_LINK[(self.network_adapter)]
        # pcap 버전 문자열 생성
        self.pcap_version = "{}.{}".format(version_major, version_minor)
        
        # 필요한 bytes 이후의 bytes를 반환함.
        return bytes_arr[self.BYTE_LENGTH:]
    
    # 정보를 출력함
    def print_info(self):
        pcap_str = "pcap version : {}".format(self.pcap_version)
        snaplen_str = "snaplen : {}".format(self.snaplen)
        ntwork_adt = "network adapter : {}".format(self.network_adapter)
        title_str = TITLE_PRINT_FORMAT.format(" Pcap Global Header Info ")
        
        print(title_str)
        print("#{}#".format(pcap_str.center(len(title_str)-2)))
        print("#{}#".format(ntwork_adt.center(len(title_str)-2)))
        print("#{}#".format(snaplen_str.center(len(title_str)-2)))
        print("#" * len(title_str))


# In[246]:


# Pcap Packet Header Class
class PcapPacketHeader:
    # Pcap Packet Header의 총 byte 길이
    BYTE_LENGTH = 16
    
    ts       = None  # timestamp
    incl_len = None  # include length
    orig_len = None  # original length
    
    def get_info_from_bytes(self, bytes_arr):
        # 필요한 bytes만 얻음
        packet_arr = bytes_arr[:self.BYTE_LENGTH]
        
        # timestamp 얻기
        ts_sec = int.from_bytes(packet_arr[:4]     ,byteorder='little')
        ts_unsec = int.from_bytes(packet_arr[4:8]  ,byteorder='little')
        # include length 얻기
        self.incl_len = int.from_bytes(packet_arr[8:12] ,byteorder='little')
        # original length 얻기
        self.orig_len = int.from_bytes(packet_arr[12:16] ,byteorder='little')
        # timestamp => datetime으로 변환
        self.ts = datetime.utcfromtimestamp(float("{}.{}".format(ts_sec, ts_unsec)))
        
        # 필요한 bytes 이후의 bytes를 반환함.
        return bytes_arr[self.BYTE_LENGTH:]
    
    # 정보를 출력함.
    def print_info(self):
        pcap_str = "timestamp : {}".format(self.ts)
        snaplen_str = "include length : {}".format(self.incl_len)
        ntwork_adt = "original length : {}".format(self.orig_len)
        title_str = TITLE_PRINT_FORMAT.format(" Packet Header Info ")
        
        print(title_str)
        print("#{}#".format(pcap_str.center(len(title_str)-2)))
        print("#{}#".format(ntwork_adt.center(len(title_str)-2)))
        print("#{}#".format(snaplen_str.center(len(title_str)-2)))
        print("#" * len(title_str))
        
    def get_packet_len(self):
        return incl_len


# In[248]:


# BinaryFile Class 생성
bfile = BinaryFile('./test3.pcap')
bfile.print_info()
# bytes array 얻기
bytes_arr , bytes_len = bfile.get_bytes_array()

# global header 및 packet header class 생성
global_header = PcapGlobalHeader()
packet_header = PcapPacketHeader()

# byte를 통해 정보 얻기
bytes_arr = global_header.get_info_from_bytes(bytes_arr)
bytes_arr = packet_header.get_info_from_bytes(bytes_arr)

# 정보 출력
global_header.print_info()
packet_header.print_info()


# In[ ]:




