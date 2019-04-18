#!/usr/bin/env python
# coding: utf-8

# os 패키지
import os
# 시스템 패키지
import sys
# 파이썬 아규먼트를 위해사용
import argparse
# 소켓 통신 모듈 불러오기 
from socket import AF_INET, socket, SOCK_STREAM
# 텍스트 포맷 관련 import
from TextFormat import bcolors, MENU_PRINT_FORMAT, TITLE_PRINT_FORMAT
# Pcap 클래스
from Pcap import Pcap

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
                    select = self.select_menu(menu_list=['1','2','3'], desc="1 : 이전페이지, 2 : 다음페이지, 3 : 이전 메뉴")
                    
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

    def socket_open(self):
        # 소켓 오픈 ( IP_V4, )
        server_sock = socket(AF_INET, SOCK_STREAM)
        server_sock.bind('', 59595)
        server_sock.listen(1)

# In[250]:

# argsparse 생성
parser = argparse.ArgumentParser(description="pcap File Parser v0.2, create by 홍지후, 정다운, 송영훈, 김가겸")
# 필수 인자 추가
parser.add_argument('--pcap', metavar='file_path', type=str, required=True, help='pcap파일의 경로를 입력해주세요.')

# 사용자로부터 전달받은 args
args = parser.parse_args()

# pcap 인자를 통해 Tui 객체 생성
Tui(args.pcap)