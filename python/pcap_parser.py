#!/usr/bin/env python
# coding: utf-8

import binascii
import os
from datetime import datetime

# 프로그래스바를 위하여 사용
from tqdm import tqdm

import sys

import argparse
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

# 메뉴 출력 포맷
MENU_PRINT_FORMAT = bcolors.OKBLUE+"{0:-^92}" + bcolors.ENDC
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
        print("{1}#{2}{0}{1}#{2}".format(path_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(size_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("-" * (len(title_str) - 9))
        
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
    
    magic_number = None  # 매직넘버
    pcap_version = None  # pcap 버전
    this_zone = None  # time_zone
    sigfigs = None   # ? (항상 0임)
    snaplen = None   # 버퍼의 크기
    network_adapter = None # link layer의 타입
    
    # bytes array를 입력하여 정보를 추출하는 메소드
    def get_info_from_bytes(self, bytes_arr):
        # 필요한 bytes 만 얻음
        header_arr = bytes_arr[:self.BYTE_LENGTH]
        
        # magic number 얻기 (4byte)
        self.magic_number = int.from_bytes(header_arr[0:4], byteorder='little')
        # pcap 메이저 버전 (2byte)
        version_major = int.from_bytes(header_arr[4:6], byteorder='little')
        # pcap 마이너 버전 (2byte)
        version_minor = int.from_bytes(header_arr[6:8], byteorder='little')
        # this zone (4byte)
        self.this_znoe = int.from_bytes(header_arr[8:12], byteorder='little')
        # sigfigs (4byte)
        self.sigfigs = int.from_bytes(header_arr[12:16], byteorder='little')
        # snaplen (4byte)
        self.snaplen = int.from_bytes(header_arr[16:20], byteorder='little')
        # 네트워크 어뎁터 (4byte)
        self.network_adapter = int.from_bytes(header_arr[20:24], byteorder='little')
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
        
        print("")
        print(title_str)
        print("{1}#{2}{0}{1}#{2}".format(pcap_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(ntwork_adt.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(snaplen_str.center(len(title_str)-11), bcolors.OKBLUE, bcolors.ENDC))
        print("-" * (len(title_str)-9))


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
        try:
            # 바이너리파일 객체 초기화
            self.binary = BinaryFile(pcap_path)
        except FileNotFoundError:
            print("올바른 파일이 아니거나 파일이 존재하지 않습니다. 다시 확인해주세요.")
            sys.exit(0)
            
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
        if(packet_id < 0):
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

# 사용자 텍스트 인터페이스 클래스
class Tui:
    # 메인메뉴 딕셔너리
    MENU = {
        '1':'1. 통신 대기(수신)',
        '2':'2. 통신 하기(송신)',
        '3':'3. 파일 내용 확인',
        '4':'4. 프로그램 종료'
    }
    
    # pcap 클래스
    pcap = ''
    
    
    def __init__(self, file_path):
        # pcap 클래스 초기화
        self.pcap = Pcap(file_path)
        # 메인루프 진행
        self.main()
    
    # 메뉴 출력
    def show_menus(self, menus):
        # 타이틀 출력
        title_str = MENU_PRINT_FORMAT.format(" 메뉴를 선택하세요. ")
        print(title_str)
        
        # 각 메뉴들을 포맷에 맞게 출력
        for menu in menus:
            print("{1}#{2}{0}{1}#{2}".format(menus[menu].center(len(title_str)-9),bcolors.OKBLUE, bcolors.ENDC))
            
        print("{1}{0}{2}".format("-" * (len(title_str)-1),bcolors.OKBLUE, bcolors.ENDC))
        print()
        
    # 메뉴 선택
    def select_menu(self, menu_list, desc='메뉴를 선택하세요.'):
        # 제대로된 input이 들어올때 까지 반복
        while(True):
            # 입력 받기
            select = input("{} : ".format(desc))
            
            # 만약 정해져있는 메뉴리스트에 포함되지않는 값이 들어올 경우 반복
            if(select not in menu_list):
                print("다시 선택해 주세요.")
                continue
            
            break
        
        # 선택된 메뉴번호 반환
        return select
    
    # 메인 기능 
    def main(self):
        # 사용자가 프로그램을 종료할 때 까지 반복
        while(True):
            # 메인 메뉴 출력
            self.show_menus(self.MENU)
            # 메뉴 선택
            select = self.select_menu(['1','2','3','4'])
            # 파일 내용확인
            if(select == '3'):
                self.show_pcap_data()
            # 프로그램 종료
            if(select == '4'):
                sys.exit(1)
            
    # pcap 파일 내용 확인 메뉴
    def show_pcap_data(self):
        # binary파일 정보 출력
        self.pcap.binary.print_info()
        # 글로벌헤더 정보 출력
        self.pcap.global_header.print_info()
        
        # 서브메뉴 딕셔너리
        SUB_MENU = {
                '1':'1. 패킷 확인하기',
                '2':'2. 이전 메뉴로 이동'
        }
        
        # 페이지 시작 번호
        start = 0
        # 페이지 종료 번호
        end= 5
        
        # 사용자가 이전메뉴로 복귀하기 전까지 무한반복
        while(True):
            # 서브메뉴 출력
            self.show_menus(SUB_MENU)
            # 서브메뉴 선택
            select = self.select_menu(['1','2'])
            
            # 패킷확인 메뉴
            if(select == '1'):
                # 사용자가 이전메뉴로 복귀하기 전까지 무한반복
                while(True):
                    # 범위 출력
                    self.pcap.print_packet_range(start, end)
                    # 이전페이지, 다음페이지, 이전메뉴중 선택
                    select = self.select_menu(menu_list=['1','2','3'], desc="1 : 이전페이지, 2 : 다음페이, 3 : 이전 메뉴")
                    
                    # 이전페이지일 경우
                    if(select == '1'):
                        # 맨첫 페이지 일 경우
                        if(start == 0):
                            print("첫번째 페이지 입니다")
                        else:
                            start -= 5
                            end -= 5
                    
                    # 다음페이지일 경우
                    elif(select == '2'):
                        start += 5
                        end += 5
                        
                    # 이전메뉴일 경우
                    else:
                        break
            
            # 이전 메뉴로 이동
            if(select == '2'):
                return
            
        
            
# In[250]:
                
# argsparse 생성
parser = argparse.ArgumentParser(description="pcap File Parser v0.2, create by 홍지후, 정다운, 송영훈, 김가겸")
# 필수 인자 추가
parser.add_argument('--pcap', metavar='file_path', type=str, required=True, help='pcap파일의 경로를 입력해주세요.')

# 사용자로부터 전달받은 args
args = parser.parse_args()

# pcap 인자를 통해 Tui 객체 생성
Tui(args.pcap)

