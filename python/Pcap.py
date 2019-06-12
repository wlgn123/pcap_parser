#!/usr/bin/env python
# coding: utf-8

from datetime import datetime
import binascii
import sys
import os
import json
import portalocker 

# 프로그래스바를 위하여 사용
from tqdm import tqdm
# 출력 포맷을 위한 import
from TextFormat import bcolors, MENU_PRINT_FORMAT, TITLE_PRINT_FORMAT
# 파일 로드 클래스
from BinaryFile import BinaryFile

def pcap_diff_checker(origin_pcap, file_pcap):
    print("########################")

def hex_to_string(hex):
    hex_str = str(binascii.b2a_hex(hex))
    new_str = ""
    hex_count = 0

    if(hex_str is None):
        return ""

    while(len(hex_str) > 2):
        hex_count += 1 

        new_str += hex_str[:2] + " "
        hex_str = hex_str[2:]

        if(hex_count == 16):
            # new_str += "\r\n"
            hex_count = 0

    new_str += hex_str

    return str(new_str)[1:].replace('\'', '').upper()

def print_hex_string(hex_str, length, sep_cout = 16):
    if(hex_str is None):
        return
        
    new_str = hex_str

    print("{1}#{2}{0}{1}#{2}".format("[ Data ]".center(length-11),bcolors.OKBLUE, bcolors.ENDC))
    while(len(new_str) > sep_cout*3):
        print("{1}#{2}{0}{1}#{2}".format(new_str[:48].center(length-11),bcolors.OKBLUE, bcolors.ENDC))
        new_str = new_str[sep_cout*3:]

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
        '''
        바이트 배열을 받아 필요한 정보를 파싱한 후, 나머지 바이트 배열을 반환합니다.
        :param bytes_arr: pcap 바이트 배열
        '''
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

    def to_dict(self, data):
        packet_dict = {
                "packetnum": self.cnt,
                "datetime": self.ts.strftime("%Y-%m-%d %H:%M:%S"),
                "incl_len": self.incl_len,
                "origin_len": self.orig_len,
                "packetdata": data.to_dict()
        }

        return packet_dict
    
    def json_to_obj(self, json_str):
        packet = json.loads(json_str.replace(",\n", ""))
        
        # 패킷 헤더 파싱
        self.cnt = packet['packetnum']
        self.ts = datetime.strptime(packet['datetime'], "%Y-%m-%d %H:%M:%S")
        self.incl_len = packet['incl_len'] 
        self.orig_len = packet['origin_len']
    
    def get_diff(self, other):
        result = False

        check_dict = {
            "ts": False,
            "incl_len": False,
            "orig_len": False
        }

        if(not(self.ts == other.ts)):
            check_dict['ts'] = True
            result = True
        
        if(not(self.incl_len == other.incl_len)):
            check_dict['incl_len'] = True
            result = True
        
        if(not(self.orig_len == other.orig_len)):
            check_dict['orig_len'] = True
            result = True

        return result, check_dict
        
# In[248]:
        
# Pcap Packet 데이터 클래스
class PcapPacketData:
    # 프로토콜 타입 딕셔너리
    PROTOCOL_TYPE = {
        '6': "TCP",
        '17': "UDP",
        "34525": "ARP"
    }
    IP_TYPE = {
        #"34525":"IP_V6",
        "2048":"IP_V4",
        "2054":"ARP"
    }
    # MAC ADDRESS 들(Source, Destination) 의 바이트 길이
    MAC_LENGTH = 12
    
    # 헤더로부터 받은 패킷의 총 바이트 길이
    incl_len = None
    protocolType = None
    type_ = None
    data = None
    header_len = 0
    
    # 목적지 Mac
    dmac = None
    # 목적지 Mac
    dip = None
    # 목적지 포트
    dport = None
    # 출발지 Mac
    smac = None
    # 출발지 IP
    sip = None
    # 출발지 포트
    sport = None
    # 서포트 하지않는 패킷 유무
    not_surport = False
    
    # Pcap Packet Data 클래스 초기화 ( include_len 을 받는다. )
    def __init__(self, incl_len):
        self.incl_len = incl_len
    
    # byte array를 통하여 필요한 정보만 추출 후, 나머지 byte array를 반환한다.
    def get_info_from_bytes(self, bytes_arr):
        self.data = bytes_arr[:self.incl_len]
        
        self.get_mac_addr()

        self.get_type()
        
        if(not(self.not_surport)):
            self.get_header()
            
        return bytes_arr[self.incl_len:]
    
    # 맥 주소를 얻는다.
    def get_mac_addr(self):
        self.dmac = str(binascii.b2a_hex(self.data[:6])).replace('b', '').replace("'",'')
        self.smac = str(binascii.b2a_hex(self.data[6:12])).replace('b', '').replace("'",'')
        
        self.dmac = "{}:{}:{}:{}:{}:{}".format(self.dmac[0:2], self.dmac[2:4], self.dmac[4:6], self.dmac[6:8], self.dmac[8:10], self.dmac[10:12])
        self.smac = "{}:{}:{}:{}:{}:{}".format(self.smac[0:2], self.smac[2:4], self.smac[4:6], self.smac[6:8], self.smac[8:10], self.smac[10:12])
        
        self.data = self.data[self.MAC_LENGTH:]

    def get_type(self):
        self.type_ = str(int.from_bytes(self.data[:2]  ,byteorder='big'))        
        if( self.type_ not in self.IP_TYPE):
            self.not_surport = True
            return
        self.data = self.data[2:]
        
        self.type_ = self.IP_TYPE[self.type_]

    def get_header(self):
        if(self.type_ == 'ARP'):
            self.protocolType = "ARP"
            self.data = ""
        else:
            # 필요없는 데이터 버림
            self.data = self.data[9:]
            # 프로토콜타입 얻어오기
            self.protocolType = str(int.from_bytes(self.data[:1]  ,byteorder='big'))
            
            if(self.protocolType not in self.PROTOCOL_TYPE):
                self.not_surport = True
                return
            self.protocolType = self.PROTOCOL_TYPE[self.protocolType]
            # 프로토콜타입 얻은 후 버림 
            self.data = self.data[3:]
            #
            self.sip = "{}.{}.{}.{}".format(self.data[0], self.data[1], self.data[2], self.data[3])
            self.data = self.data[4:]
            
            self.dip = "{}.{}.{}.{}".format(self.data[0], self.data[1], self.data[2], self.data[3])
            self.data = self.data[4:]

            
            if(self.protocolType == 'TCP'):
                self.header_len = int("{:0>8b}".format(self.data[12])[:4], 2) * 4
            else:
                self.header_len = 8

            self.dport  = str(int.from_bytes(self.data[:2]  ,byteorder='big'))
            self.sport = str(int.from_bytes(self.data[2:4]  ,byteorder='big'))
            
            self.data = hex_to_string(self.data[self.header_len:])

    # 정보를 출력함.
    def print_info(self):
        smac_str = "Source Mac Address : {}".format(self.smac)
        dmac_str = "Dest Mac Address : {}".format(self.dmac)
        type_str = "Type : {}".format(self.type_)
        proto_str = "Protocol : {}".format(self.protocolType)
        sip_str = "Source IP : {}".format(self.sip)
        dip_str = "Dest IP : {}".format(self.dip)
        sport_str = "Source Port : {}".format(self.sport)
        dport_str = "Dest Port : {}".format(self.dport)
        
        title_str = TITLE_PRINT_FORMAT.format(" Packet Data Info ")
        
        print(title_str)
        print("{1}#{2}{0}{1}#{2}".format(smac_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(dmac_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(type_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(proto_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(sip_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(dip_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(sport_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print("{1}#{2}{0}{1}#{2}".format(dport_str.center(len(title_str)-11),bcolors.OKBLUE, bcolors.ENDC))
        print_hex_string(self.data, len(title_str))
        print("{1}{0}{2}".format("-" * (len(title_str)-9),bcolors.OKBLUE, bcolors.ENDC))
        print()

    def to_dict(self):
        data_dict = {
                "type": self.type_,
                "smac": self.smac,
                "dmac": self.dmac,
                "sip": self.sip,
                "dip": self.dip,
                "protocol": self.protocolType,
                "sport": self.sport,
                "dport": self.dport,
                "data": self.data
            }

        return data_dict
    
    def json_to_obj(self, json_str):
        packet = json.loads(json_str.replace(",\n", ""))["packetdata"]
        
        # 프로토콜 타입
        self.protocolType = packet['protocol']
        # 타입
        self.type_ = packet['type']
        # 데이터
        self.data = packet['data']
        # 목적지 Mac
        self.dmac = packet['dmac']
        # 목적지 IP
        self.dip = packet['dip']
        # 목적지 포트
        self.dport = packet['dport']
        # 출발지 Mac
        self.smac = packet['smac']
        # 출발지 IP
        self.sip = packet['sip']
        # 출발지 포트
        self.sport = packet['sport']

    def get_diff(self, other):
        result = False

        check_dict = {
                "type": False,
                "smac": False,
                "dmac": False,
                "sip": False,
                "dip": False,
                "protocol": False,
                "sport": False,
                "dport": False,
                "data": False
        }

        if(not(self.type_ == other.type_)):
            check_dict['type'] = True
            result = True

        if(not(self.smac == other.smac)):
            check_dict['smac'] = True
            result = True
        
        if(not(self.dmac == other.dmac)):
            check_dict['dmac'] = True
            result = True
        
        if(not(self.sip == other.sip)):
            check_dict['sip'] = True
            result = True

        if(not(self.dip == other.dip)):
            check_dict['dip'] = True
            result = True

        if(not(self.protocolType == other.protocolType)):
            check_dict['protocol'] = True
            result = True

        if(not(self.sport == other.sport)):
            check_dict['sport'] = True
            result = True
            
        if(not(self.dport == other.dport)):
            check_dict['dport'] = True
            result = True

        if(not(self.data == other.data)):
            check_dict['data'] = True
            result = True

        return result, check_dict
        
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
    # pcap이 로드되었는지 여부
    loaded = False
    # json 파일이름
    json_file_name = None 

    #  Pcap 초기화 ( pcap 파일의 경로 )
    def __init__(self, pcap_path):
        try:
            # 바이너리파일 객체 초기화
            self.binary = BinaryFile(pcap_path)

            if(self.binary.path is not None):
                # 바이너리파일 객체로부터 pcap파일의 byte array와 byte의 길이를 받음.
                self.byte_arr, self.byte_len = self.binary.get_bytes_array()
                # 글로벌 해더 객체 초기화 
                self.global_header = PcapGlobalHeader()

                # byte_array를 글로벌 헤더에 전달 -> 글로벌 헤더 내용 생성 -> 나머지 byte_array 반환
                self.byte_arr = self.global_header.get_info_from_bytes(self.byte_arr)
                
                # packet 헤더 및 데이터 얻기
                self.get_packets()
                # 로드성공 
                self.loaded = True
        except FileNotFoundError:
            print("올바른 파일이 아니거나 파일이 존재하지 않습니다. 다시 확인해주세요.")
            self.loaded = False
        except Exception:
            print("pcap 파일을 불러오지 못했습니다.")
            self.loaded = False
    
    # packet 헤더 리스트 및 pakcet 데이터 리스트 초기화
    def get_packets(self):
        # prograss Bar를 위한 객체
        pbar = tqdm(total=self.byte_len)
        # json 저장 파일 명
        self.json_file_name = "{}.json".format(self.binary.name)
        try:
            # dump 파일 oepn
            with open(self.json_file_name + ".dump", 'w') as f:
                f.write('[\n')
                f.write(" " * 100)
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
                    
                    # 지원하지 않는 패킷일 경우
                    if(data.not_surport):
                        self.cnt -= 1
                        continue
                    else:
                        if(self.cnt > 1):
                            f.write(",\n")

                        # packet to dict
                        packet_dict = header.to_dict(data)
                        f.write(json.dumps(packet_dict))

                    # list에 append
                    # self.header_list.append(header)
                    # self.data_list.append(data)
                    
                    # prograssBar 업데이트
                    pbar.update(header.BYTE_LENGTH + data.incl_len)
                # json array 닫기
                f.write("\n]")
                # 두번째 byte로 이동
                f.seek(2)
                # pcap 글로벌 헤더 내용 출력
                pcap_dict = {
                    "version": self.global_header.pcap_version,
                    "snaplen": self.global_header.snaplen,
                    "packetCnt": self.cnt
                }
                f.write(json.dumps(pcap_dict) + ",\n")
            
            # 라인 개수 변수
            line_cnt = 0
            # dump 복사, 기존의 파일을 복사하여 새로 생성함
            with open(self.json_file_name + ".dump", 'r') as in_file, open(self.json_file_name, 'w') as out_file:
                while True:
                    new_line = in_file.readline()

                    if(not(new_line)):
                        break

                    if(line_cnt < 3):
                        new_line = new_line.strip(" ")

                    out_file.write(new_line)

                    line_cnt = line_cnt + 1
                    
            # dump 파일 삭제
            os.remove(self.json_file_name + ".dump")
            # prograssBar 종료
            pbar.close()

        except json.JSONDecodeError as e:
            print("json 파싱중 에러가 발생했습니다.")
            print(e)
            self.loaded = False
        except Exception as e:
            print(e)

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
        # json파일을 통해 출력
        with open(self.json_file_name, 'r') as f:
            line = f.readlines()

            for i in range(start + 2, end + 2):
                # 헤더 파싱
                header = PcapPacketHeader()
                header.json_to_obj(line[i])
                # 데이터 파싱
                data = PcapPacketData(header.incl_len)
                data.json_to_obj(line[i])

                header.print_info()
                data.print_info()
    
    def save(self):
        self.json_file_name = "{}.json".format(self.binary.name)
        
        with open(self.json_file_name, 'w') as f:
            f.write('[ \n')

            pcap_dict = {
                "version": self.global_header.pcap_version,
                "snaplen": self.global_header.snaplen,
                "packetCnt": self.cnt
            }
            
            f.write(json.dumps(pcap_dict)+", \n")
            
            # 패킷 해더 & 데이터 반복
            for i in range(self.cnt):
                header = self.header_list[i]
                data = self.data_list[i]

                packet_dict = header.to_dict(data)

                if(i == self.cnt -1 ):
                    f.write(json.dumps(packet_dict)+" \n ]")
                else:
                    f.write(json.dumps(packet_dict)+", \n")

    def json_to_pcap(self, file_name = None):
        json_dict = ""
        self.json_file_name = file_name
        
        # 파일이름이 지정된 경우 json 파일 내용 불러오기
        if(file_name is not None):
            with open(file_name, 'r') as f:
                json_dict = json.loads(f.read())
        else:
            print("file_name가 없습니다.")

        with open(file_name, 'r') as f:
            line = f.readlines()

            header = line[1]
            json_dict = json.loads(header.replace(",\n", ""))

            # 글로벌 헤더 초기화
            self.global_header = PcapGlobalHeader()

            # 글로벌 헤더 내용 파싱
            self.global_header.magic_number = 0
            self.global_header.network_adapter = ''
            self.global_header.pcap_version = json_dict['version']
            self.global_header.snaplen = json_dict['snaplen']
            self.cnt = json_dict['packetCnt']

        self.global_header.print_info()


#%%
