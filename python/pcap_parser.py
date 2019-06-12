#!/usr/bin/env python
# coding: utf-8

# os 패키지
import os
# 시스템 패키지
import sys
# 파이썬 아규먼트를 위해사용
import argparse
# 소켓 통신 모듈 불러오기 
from socket import AF_INET, socket, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
# 텍스트 포맷 관련 import
from TextFormat import bcolors, MENU_PRINT_FORMAT, TITLE_PRINT_FORMAT
# Pcap 클래스
from Pcap import Pcap, PcapPacketHeader, PcapPacketData

import traceback

from tqdm import tqdm

# In[245]:

# 소켓 서버 클래스(리시버)
class SocketServer:
    sock = None
    ip = None
    connected = False

    def __init__(self, ip = None, port=59595):
        try:
            if(ip is None):
                print("IP를 입력해주세요.")
            else:
                self.ip = ip

            # socket 설정
            sock = socket(AF_INET, SOCK_STREAM)
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.bind((self.ip, port))
            sock.settimeout(60)

            self.sock = sock

            print("통신 대기를 위한 소켓이 {}:{} 를 통해 열렸습니다.".format(self.ip, port))
        except Exception as e:
            print(e)

    def connect(self):
        self.sock.listen(0)
        print("CONNECT WAIT...")
        client, addr = self.sock.accept() 
        client.settimeout(60)

        print("CONNECTED FROM {}".format(addr))
        self.connected = True

        return client

    def send(self, client, data):
        client.sendall(data.encode())

    def wait_pcap(self):
        file_pcap = Pcap(None)

        client = self.connect()
        
        # 받은 json 파일을 저장할 파일명
        file_name = None

        try:
            BUF_SIZE = 1024
            
            command = client.recv(4)

            if(command == b'FILE'):
                data = client.recv(BUF_SIZE)
                file_name = data.decode('utf-8')
                
                if(b'{' in data):
                    file_name = file_name.split('[')[0]
                    data = data[len(file_name):]
                else:
                    data = b''
                print("## " + file_name)

                file_name = "recived_"+ file_name
                
                with open(file_name, 'wb') as f:
                    f.write(data)

                    while True:
                        data = client.recv(BUF_SIZE)
                        if not data:
                            break
                        if(b'EOF' in data):
                            f.write(data[:-3])
                            break

                        f.write(data)
                print("파일 수신 성공 - 저장된 파일명 : {}".format(file_name))
                
                file_pcap.json_to_pcap(file_name=file_name)
                file_pcap.loaded = True

                client.send(b"EOF")

                check = int(client.recv(1))
                
                if(check == 1):
                    # prograss Bar를 위한 객체
                    pbar = tqdm(total=file_pcap.cnt)

                    with open(file_name, 'r') as f:
                        line = f.readlines()
                        count = 1
                        un_match_cnt = 0
                        un_match_index = []

                        while(True):
                            count = count + 1
                            recv = client.recv(10)

                            if(b'EOF' in recv):
                                break

                            packet_len = int(recv.strip())
                            
                            recv_json = client.recv(packet_len).decode('utf-8')
                            now_json = line[count]
                            
                            while(len(recv_json) < packet_len):
                                recv_json += client.recv(packet_len- len(recv_json)).decode('utf-8')

                            recv_header = PcapPacketHeader()
                            recv_header.json_to_obj(recv_json)
                            
                            recv_data = PcapPacketData(recv_header.incl_len)
                            recv_data.json_to_obj(recv_json)

                            now_header = PcapPacketHeader()
                            now_header.json_to_obj(now_json)

                            now_data = PcapPacketData(now_header.incl_len)
                            now_data.json_to_obj(now_json)

                            header_check_result, header_check_dict = now_header.get_diff(recv_header)
                            data_check_result, data_check_dict = now_data.get_diff(recv_data)

                            if(header_check_result or data_check_result):
                                un_match_cnt = un_match_cnt + 1
                                un_match_index.append(count-1)

                                client.send(b"1")
                                self.send(client, "{:<10}".format(len(line[count])))
                                self.send(client, line[count])

                                recv_header.print_info()

                                if(header_check_result):
                                    now_header.print_info()

                                    for key in header_check_dict:
                                        if(header_check_dict[key]):
                                            print("### {0} 불일치 ###".format(key))

                                if(data_check_result):
                                    recv_data.print_info()
                                    now_data.print_info()

                                    for key in data_check_dict:
                                        if(data_check_dict[key]):
                                            print("### {0} 불일치 ###".format(key))

                                continue_check = client.recv(1)

                                if(continue_check == b'0'):
                                    # EOF 신호받기
                                    EOF = client.recv(3)
                                    break
                            else:
                                client.send(b"0")

                            pbar.update()

                        print("###########################################")
                        print("### 패킷 비교 결과 ###")
                        print("패킷 갯수 {}, 불일치 패킷 {} , 불일치 패킷 번호 {}".format(count-2, un_match_cnt, un_match_index))

                return file_pcap

        except ConnectionAbortedError as e:
            print("연결 중단")
            print(str(e))
        except ConnectionRefusedError as e:
            print("연결 도중 문제가 발생했습니다. : ConnectionRefusedError")
            print(str(e))
        except ConnectionResetError as e:
            print("연결이 초기화 되었습니다. : ConnectionResetError")
            print(str(e))
        except ConnectionError:
            print("연결 도중 문제가 발생했습니다. : ConnextionError")
            print(str(e))
        except Exception as e:
            print(str(e))
            print(traceback.format_exc())
        finally:
            client.close()

        self.sock.close()
        self.connected = False
        
        return file_name

# 소켓 클라이언트 클래스(센더)
class SocketClient:
    sock = None
    connected = False
    def __init__(self, host, port=59595):
        sock = socket(AF_INET, SOCK_STREAM)
        self.host = host
        self.port = port
        self.sock = sock

    def connect(self):
        print("WAIT CONNECTION")
        self.sock.connect((self.host, self.port))
        self.connected = True
        print("CONNECTION SUCCESS")

    def send(self, data):
        if(self.connected):
            self.sock.sendall(data.encode())

    def send_file(self, file_name):
        if(self.connected):
            try:
                # 버퍼 사이즈 지정
                BUF_SIZE = 1024
                # 파일 전송 신호 보내기
                self.send("FILE")
                # 파일 이름 전송
                self.send(file_name)
                # 파일 열기
                f = open(file_name, 'rb')
                l = f.read(BUF_SIZE)

                # 파일의 내용을 버퍼사이즈 만큼 반복 통신, EOF(End Of File)일 경우 반복문 종료
                while(l):
                    self.sock.send(l)
                    l = f.read(BUF_SIZE)

                # 파일 전송 종료 신호 보내기
                self.sock.send(b"EOF")

                # 서버측으로부터 파일전송이 완료되었는지 신호 받기
                eof = self.sock.recv(BUF_SIZE)

                # 서버측으로부터 파일전소 완료 신호가 잘 도착했는지 확인
                if(eof == b'EOF'):
                    print("파일 송신 성공")
                else:
                    print("파일 송신 실패, 다시 시도해주세요.")
                    raise Exception()

                check = True

                while(True):
                    select = input("패킷 비교 1, 통신 종료 0 : ")
                    
                    if(select == "1"):
                        break
                    elif(select == "0"):
                        check = False
                        break
                    else:
                        print("잘못된 입력입니다. 다시 입력해주세요.")
                        continue

                if(not(check)):
                    self.send("0")
                else:
                    self.send("1")

                with open(file_name, 'r') as f:
                    line = f.readlines()

                    count = 1
                    un_match_cnt = 0
                    un_match_index = []

                    for i in range(2, len(line)-1):
                        count = count + 1

                        self.send("{:<10}".format(len(line[i])))
                        self.send(line[i])

                        check = int(self.sock.recv(1))
                        
                        if(check == 1):
                            recv = self.sock.recv(10)

                            packet_len = int(recv.strip())
                            
                            now_json = self.sock.recv(packet_len).decode('utf-8')

                            while(len(now_json) < packet_len):
                                now_json += self.sock.recv(packet_len- len(now_json)).decode('utf-8')

                            recv_json = line[i]

                            recv_header = PcapPacketHeader()
                            recv_header.json_to_obj(recv_json)
                            
                            recv_data = PcapPacketData(recv_header.incl_len)
                            recv_data.json_to_obj(recv_json)

                            now_header = PcapPacketHeader()
                            now_header.json_to_obj(now_json)

                            now_data = PcapPacketData(now_header.incl_len)
                            now_data.json_to_obj(now_json)

                            header_check_result, header_check_dict = now_header.get_diff(recv_header)
                            data_check_result, data_check_dict = now_data.get_diff(recv_data)

                            if(header_check_result or data_check_result):
                                un_match_cnt = un_match_cnt + 1
                                un_match_index.append(count-1)

                                recv_header.print_info()

                                if(header_check_result):
                                    now_header.print_info()

                                    for key in header_check_dict:
                                        if(header_check_dict[key]):
                                            print("{0} 불일치".format(key))

                                if(data_check_result):
                                    recv_data.print_info()
                                    now_data.print_info()

                                    for key in data_check_dict:
                                        if(data_check_dict[key]):
                                            print("{0} 불일치".format(key))

                                continue_check = True

                                while(True):
                                    continue_select = input("계속하기 1, 통신 종료 0 : ")
                                    
                                    if(continue_select == "1"):
                                        self.send("1")
                                        break
                                    elif(continue_select == "0"):
                                        self.send("0")
                                        continue_check = False
                                        break
                                    else:
                                        print("잘못된 입력입니다. 다시 입력해주세요.")
                                        continue

                                if(not(continue_check)):
                                    break

                    print("###########################################")
                    print("### 패킷 비교 결과 ###")
                    print("패킷 갯수 {}, 불일치 패킷 {} , 불일치 패킷 번호 {}".format(count-2, un_match_cnt, un_match_index))

                self.send("EOF")

            except ConnectionAbortedError as e:
                print("연결 중단")
                print(str(e))
            except ConnectionRefusedError as e:
                print("연결 도중 문제가 발생했습니다. : ConnectionRefusedError")
                print(str(e))
            except ConnectionResetError as e:
                print("연결이 초기화 되었습니다. : ConnectionResetError")
                print(str(e))
            except ConnectionError:
                print("연결 도중 문제가 발생했습니다. : ConnextionError")
                print(str(e))
            except Exception as e:
                print(str(e))
                print(traceback.format_exc())
            except Exception as e:
                print(str(e))
            finally:
                f.close()
                self.close()

    def close(self):
        self.sock.close()
        self.connected = False

# In[245]:

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
    def show_menus(self, menus, use_menus=['1','2','3','4']):
        # 타이틀 출력
        title_str = MENU_PRINT_FORMAT.format(" 메뉴를 선택하세요. ")
        print(title_str)
        
        # 각 메뉴들을 포맷에 맞게 출력
        for menu in menus:
            if(menu not in use_menus):
                continue
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
        if(self.pcap.loaded):
            print("")
            # self.pcap.save()
        else:
            print()
            print("--pcap 명령을 통해 pcap파일을 불러오지 않았습니다.")
            print("'통신 하기(송신)'와 '파일 내용 확인' 메뉴를 이용할 수 없습니다.")

        # 사용자가 프로그램을 종료할 때 까지 반복
        while(True):
            # 메뉴 선택
            if(self.pcap.loaded):
                # 메인 메뉴 출력
                self.show_menus(self.MENU)
                select = self.select_menu(['1','2','3','4'])
            else:
                # 메인 메뉴 출력 (1번 메뉴와 4번 메뉴만)
                self.show_menus(self.MENU, ['1','4'])
                select = self.select_menu(['1', '4'])

            # 통신대기(수신)
            if(select == '1'):
                ip = input("현재 컴퓨터의 IP를 입력해주세요. : ")
                reciver = SocketServer(ip)
                self.pcap = reciver.wait_pcap()
                
            # 통신하기(송신)
            if(select == '2'):
                # IP 입력 요청
                ip = input("상대 컴퓨터의 IP를 입력해주세요. : ")

                # 소켓 클라이언트 생성 ( IP: 사용자 입력, 포트 : 59595로 통일)
                sender = SocketClient(ip)
                # 소켓 연결
                sender.connect()
                # json 파일 전송
                sender.send_file(self.pcap.json_file_name)

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
        
        page_per_packets = 4
        
        now_page = 1
        tot_len = self.pcap.cnt
        tot_page = int(tot_len / page_per_packets)
        
        # 마지막 페이지가 페이지별 패킷 갯수로 나뉘는지 확인( 3개, 2개, 등..)
        last =  page_per_packets % tot_page
        
        if(last > 0):
            tot_page += 1
                    
        # 페이지 시작 번호
        start = 0
        # 페이지 종료 번호
        end= page_per_packets
        
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
                    select = self.select_menu(menu_list=['1','2','3','4','5'], desc="({} / {}) 1: 첫번째페이지    2: 이전페이지    3: 다음페이지    4: 마지막페이지    5: 이전 메뉴".format(now_page, tot_page))

                    os.system('cls')
                    
                    # 첫번째 페이지 이동
                    if(select == '1'):
                        now_page = 1
                        start = 0
                        end = page_per_packets
                    # 마지막 페이지 이동
                    elif(select == '4'):
                        now_page = tot_page
                        start = ((tot_page * page_per_packets) - page_per_packets)
                        end = (tot_page * page_per_packets) -1
                    # 이전페이지일 경우
                    elif(select == '2'):
                        # 맨첫 페이지 일 경우
                        if(start == 0):
                            print("첫번째 페이지 입니다")
                        else:
                            start -= page_per_packets
                            end -= page_per_packets
                            now_page -= 1 
                    
                    # 다음페이지일 경우
                    elif(select == '3'):
                        if(now_page >= tot_page):
                            print("마지막 페이지 입니다.")
                        else:
                            start += page_per_packets
                            end += page_per_packets
                            
                            if(end >= tot_len):
                                end = tot_len
                                
                            now_page += 1
                    
                    # 이전메뉴일 경우
                    else:
                        break
            
            # 이전 메뉴로 이동
            if(select == '2'):
                return
# In[250]:

# argsparse 생성
parser = argparse.ArgumentParser(description="pcap File Parser v0.3, create by 홍지후, 정다운, 송영훈, 김가겸, 고채훈, 장인기")
# pcap 파일 인자 추가
parser.add_argument('--pcap', metavar='pcap_file_path', type=str, required=False, help='pcap파일의 경로를 입력해주세요.')
# json 파일 인자 추가
parser.add_argument('--json', metavar='json_file_path', type=str, required=False, help='json파일의 경로를 입력해주세요.')

# 사용자로부터 전달받은 args
args = parser.parse_args()

# pcap 인자를 통해 Tui 객체 생성
Tui(args.pcap)