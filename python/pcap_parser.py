#!/usr/bin/env python
# coding: utf-8

import binascii
import os
from datetime import datetime

# 프로그래스바를 위하여 사용
from tqdm import tqdm
# In[243]:

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
# 타이틀 출력 포맷
TITLE_PRINT_FORMAT = bcolors.OKBLUE+"{0:-^100}" + bcolors.ENDC

# In[244]:    

# BinaryFile Class
class BinaryFile:
    # 파일 경로
    path = None
    # 파일 사이즈
    file_size = None
    # 파일 -> 바이트 어레이
    bytes_array = None
    
    # 초기화 ( 파일 경로 )
    def __init__(self, path):
        string = None
        self.path = path
        self.file_size = os.stat(path).st_size * 0.001
        
        # 파일읽음 -> 바이트 어레이 -> self.bytes_array 에 담기
        with open(path, 'rb') as f:
            string = f.read()
            
        self.bytes_array = string
    
    # 헥스 단위 여백을 추가하기 위한 메소드
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
    
    # 파일 Info 출력
    def print_info(self):
        path_str = "file path : {}".format(self.path)
        size_str = "file size : {}KB".format(self.file_size)
        title_str = TITLE_PRINT_FORMAT.format(" FILE INFO ")
        
        print(title_str)
        print("#{}#".format(path_str.center(len(title_str)-2)))
        print("#{}#".format(size_str.center(len(title_str)-2)))
        print("-" * len(title_str))
        
    # 파일의 byte array를 반환한다. 추가로 byte array의 길이도 반환함.
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
        print("-" * len(title_str))


# In[246]:


# Pcap Packet Header Class
class PcapPacketHeader:
    # Pcap Packet Header의 총 byte 길이
    BYTE_LENGTH = 16
    
    ts       = None  # timestamp
    incl_len = None  # include length
    orig_len = None  # original length
    
    cnt = 0
    
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
        title_str = TITLE_PRINT_FORMAT.format(" PacketNum : {}  Packet Header Info  ".format(self.cnt))
        
        print(title_str)
        print("{1}#{2}{0}{1}#{2}".format(pcap_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(ntwork_adt.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(snaplen_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
    
    # incl_len 겟터
    def get_packet_len(self):
        return incl_len


# In[248]:
        
# Pcap Packet 데이터 클래스
class PcapPacketData:
    # 프로토콜 타입 딕셔너리
    PROTOCOL_TYPE = {
        "": "ARP",
    }
    # MAC ADDRESS 들(Source, Destination) 의 바이트 길이
    MAC_LENGTH = 12
    
    # 헤더로부터 받은 패킷의 총 바이트 길이
    incl_len     = None
    protocolType = None
    data         = None
    
    # 목적지 Mac
    dmac = None
    # 출발지 Mac
    smac = None
    
    # Pcap Packet Data 클래스 초기화 ( include_len 을 받는다. )
    def __init__(self, incl_len):
        self.incl_len = incl_len
    
    # byte array를 통하여 필요한 정보만 추출 후, 나머지 byte array를 반환한다.
    def get_info_from_bytes(self, bytes_arr):
        self.data = bytes_arr[:self.incl_len]
        
        self.get_mac_addr()
        
        return bytes_arr[self.incl_len:]
    
    # 맥 주소를 얻는다.
    def get_mac_addr(self):
        self.dmac = binascii.b2a_hex(self.data[:6])
        self.smac = binascii.b2a_hex(self.data[6:12])
        
        self.data = self.data[self.MAC_LENGTH:]
        
    # 정보를 출력함.
    def print_info(self):
        smac_str = "Source Mac Address : {}".format(self.smac)
        dmac_str = "Dest Mac Address : {}".format(self.dmac)
        title_str = TITLE_PRINT_FORMAT.format(" Packet Data Info ")
        
        print(title_str)
        print("{1}#{2}{0}{1}#{2}".format(smac_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(dmac_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}{0}{2}".format("-" * (len(title_str)-9),bcolors.OKBLUE, bcolors.ENDC))
        print()
        
# In[249]:

# Pcap 클래스
class Pcap:
    # 바이너리 파일 변수
    binary = None
    # 글로벌 해더 변수
    global_header = None
    # 패킷 헤더 리스트
    header_list = []
    # 패킷 데이터 리스트
    data_list = []
    # 총 패킷 갯수
    cnt = 0
    
    #  Pcap 초기화 ( pcap 파일의 경로 )
    def __init__(self, pcap_path):
        # 바이너리파일 객체 초기화
        self.binary = BinaryFile(pcap_path)
        # 바이너리파일 객체로부터 pcap파일의 byte array와 byte의 길이를 받음.
        self.byte_arr, self.byte_len = self.binary.get_bytes_array()
        # 글로벌 해더 객체 초기화 
        self.global_header = PcapGlobalHeader()
        # byte_array를 글로벌 헤더에 전달 -> 글로벌 헤더 내용 생성 -> 나머지 byte_array 반환
        self.byte_arr = self.global_header.get_info_from_bytes(self.byte_arr)
        
        # packet 헤더 및 데이터 얻기
        self.get_packets()
    
    # packet 헤더 리스트 및 pakcet 데이터 리스트 초기화
    def get_packets(self):
        # prograss Bar를 위한 객체
        pbar = tqdm(total=self.byte_len)
        
        # byte_array를 모두다 소모할때까지 반복
        while(len(self.byte_arr) > 0):
            # packet 갯수 증가
            self.cnt += 1
            
            # 패킷 해더 객체 생성
            header = PcapPacketHeader()
            # 패킷 해더 넘버 지정
            header.cnt = self.cnt
            
            # byte_array를 패킷 헤더에 전달 -> 패킷 헤더 내용 생성 -> 나머지 byte_array 반환
            self.byte_arr = header.get_info_from_bytes(self.byte_arr)
            
            # byte_array를 패킷 데이터에 전달 -> 패킷 데이터 내용 생성 -> 나머지 byte_array 반환
            data = PcapPacketData(header.incl_len)
            self.byte_arr = data.get_info_from_bytes(self.byte_arr)   
            
            # list에 append
            self.header_list.append(header)
            self.data_list.append(data)
            
            # prograssBar 업데이트
            pbar.update(header.BYTE_LENGTH + data.incl_len)
        # prograssBar 종료
        pbar.close()
    
    # 모든 패킷 정보 출력
    def print_all_packets(self):
        for i in range(self.cnt):
            self.header_list[i].print_info()
            self.data_list[i].print_info()
        print()
    # 지정된 패킷(패킷번호를 통하여) 정보 출력
    def print_packet(self, packet_id):
        # 만약 패킷번호가 패킷총갯수보다 클 경우 메소드 종료
        if(packet_id > self.cnt):
            return
        # 만약 패킷번호가 1보다 작다면 메소드 종료
        if(packet_id < 1):
            return
        
        print()
        # 패킷번호에 맞는 해더와 데이터의 정보 출력.
        self.header_list[packet_id].print_info()
        self.data_list[packet_id].print_info()
    
    # 패킷 범위 출력
    def print_packet_range(self, start, end):
        print()
        
        for packet_id in range(start, end):
            # 패킷번호에 맞는 해더와 데이터의 정보 출력.
            self.header_list[packet_id].print_info()
            self.data_list[packet_id].print_info()
            
    
    def save(self):
        # 추가 필요 
        return False



# In[250]:
pcap = Pcap('./test2.pcap')


pcap.print_packet_range(0, 10)

#pcap.print_all_packets()
