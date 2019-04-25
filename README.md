# python 개발환경 세팅
1. # 아나콘다 다운로드
- [다운로드 링크](https://www.anaconda.com/distribution/)
- 윈도우 키 누른 후 Anaconda Prompt 실행

2. # 가상환경 생성 ( pyhon 3.7 버전 )
- conda create -n py37 python=3.7

3. # 가상환경 접속
- activate py37

4. # IDE 설치
- activate py37
- conda install spyder

5. # 필요 패키지 설치
- pip install tqdm

6. # IDE 실행
- activate py37
- spyder 엔터
- 굳이 py37 환경을 activate 하는 이유는 spyder IDE에서 py37 환경을 이용하기 위해서이다.

7. # 소스 파일 실행
- git을 클론한다.
- '3' 을 진행하여 가상환경에 접속한다.
- cmd 명령어를 통해 깃 폴더의 python으로 이동한다.
- 실행 명령어: python pcap_parser.py
- 필수 옵션: --pcap pcap파일경로
- 도움말: -help, --help
- ![도움말](/img/help.PNG)
- 예제: python pcap_parser.py --pcap ./test3.pcap

- 실행화면 ![실행화면](/img/run3.PNG) ![실행화면](/img/run4.PNG)


# 빌드 파일 실행

- 빌드 파일은 별도의 파이썬 환경을 설치하지않아도 사용 가능하다.

- 깃을 클론한다.

- cmd를 킨다.

- cd 명령어로 깃 클론 폴더 하위의 dist 폴더로 이동.

- pcap_parser.exe --pcap pcap파일경로

- ex : pcap_parser.exe --pcap ../python/test3.cap

- ![빌드파일실행](/img/run_build_file.PNG)


# 기타
1. # 글로벌 헤드 뜯어보기
- spyder를 실행 시킨다.
- pcap_parser.py를 열어서 실행시킨다.
- 우측 하단의 콘솔창에 아래 코드를 입력한다
- binascii.b2a_hex(bfile.bytes_array[:24])
- binascii 모듈을 이용하여 byte를 hex로 변환하는 코드이다.
   글로벌 헤더의 길이가 24byte이므로 0번째인덱스에서 23번째 인덱스만을 변환하였다.
- 출력된 hex값을 분석해본다.


2. # 현재까지 진행된 척도
- Binary 파일을 다루기 위한 클래스 생성
- Pcap binary 파일의 Global Header 분석
- Pcap Packet Header의 분석
- 각 Header별 클래스 생성
- 각 클래스를 Pcap이라는 클래스로 묶음.

3. # 추후 진행해야되는 사항
- packer body 부분의 분석 필요
- 파일 read 및 write, packet 분석 시 발생할 수 있는 Exception 분석
- 각 Exception을 캐치하기 위한 알고리즘 분석
- pcap 저장 및 로드 기능 추가
- pcap 을 로드 한 후, 다른 pcap 클래스와 비교할 수 있는 기능이 필요


4. # REFERENCE
- [용팔이세상 - pcap 분석](https://dragon82.tistory.com/10)
- [Hison.me - pcap 분석](https://hiseon.me/2018/01/30/pcap-basic-example/)
- [ehclub.co.kr - pcap 분석](https://ehclub.co.kr/2548)
- [pcak wiki - pcap 분석](https://en.wikipedia.org/wiki/Pcap)
- [패킷인사이드 - 리틀인디언과 빅인디언의 차이](http://www.packetinside.com/2010/10/%EB%A6%AC%ED%8B%80%EC%97%94%EB%94%94%EC%95%88little-endian%EA%B3%BC-%EB%B9%85%EC%97%94%EB%94%94%EC%95%88big-endian%EC%9D%B4%ED%95%B4%ED%95%98%EA%B8%B0.html)
- [Libpcap File Format Wiki](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [링크계층 헤더의 종류](https://www.tcpdump.org/linktypes.html)


5. # pcap 파일 분석
- ![글로벌헤더](/img/global_header.PNG)
- 그림 출처 : https://wiki.wireshark.org/Development/LibpcapFileFormat
- 글로벌 헤더의 구조이다.
- magic_number(4byte) : pcap 파일임을 명시하는 바이트이다. 항상 0xa1b2c3d4 (little endian) 또는 0xd4c3b2a1 (big endian)을 가지고있다.
- version_major(2byte) : pcap 파일 포맷의 메이저버전이다. 현재 메이저 버전은 2이다.
- version_minor(2byte) : pcap 파일 포맷의 마이너버전이다. 현재 마이너 버전은 4이다
- major버전과 minor버전을 합치면 버전을 알 수있는데 현재 버전은 2.4가된다.
- thiszone(4byte): thizone은 파일을 저장한 컴퓨터의 시간과 GMT(UTC) 시간과의 차이를 나타낸다. 특별한경우가 아니라면 0값으로 박힌다.
- sigfigs(4byte): 캡쳐했을때의 timestamp의 정확성이다. 0으로 고정되어 들어온다.
- snaplen(4byte): 캡쳐 된 패킷 바이트의 최대 길이이다. (패킷의 길이가 snaplen을 넘을 수 없다.)
- network(4byte): 링크계층의 헤더 유형이다.(1일 경우 이더넷 ...)
- 글로벌 헤더의 총 길이는 24byte인것을 알 수있다.

#
- ![패킷헤더](/img/packet_header.PNG)
- 그림 출처 : https://wiki.wireshark.org/Development/LibpcapFileFormat
- 패킷 헤더의 구조이다.
- ts_sec(4byte) : 패킷의 타임스탬프(second)
- ts_usec(4byte) : 패킷의 타임스템프 (microsecond)
- incl_len(4byte) : 패킷을 저장했을때의 byte(8bit = octets) 갯수이다.
- origin_len(4byte) : 패킷의 길이이다.
- incl_len은 snaplen보다 클 수 없다. 또한 origin_len보다 클 수 없다.
- origin_len은 incl_len과 snaplen보다 클 수있다. ( wireshark에서 설정한 패킷의 최대 길이(snaplen)보다 실제 패킷의 길이(origin_len)가 클 경우)
fsdf

# 프로젝트 텍스트 파일 저장 포맷
   -  json 형식의 텍스트 포맷을 사용.
   - 텍스트 포맷은 pcap_parse.json을 통해 확인 가능.
   - ![패킷헤더](/img/pcap_save_file_format.png)


# pcap_parse V0.1 (Old)
   - Binary 클래스, Pcap 클래스, PcapPacketHeader 클래스, PcapPacketData 클래스 생성
   - 각 클래스 별 정보 출력 기능 추가. ![](/img/info_cap_1.PNG)
   - 파일 로드 시, prograss Bar 기능 추가 ![](/img/prograssBar.PNG)

# pcap_parse V0.2 (Current)
   - 텍스트 사용자 인터페이스를 위한 Tui 클래스 개발 ![실행화면](/img/run3.PNG)

   - argsparser 추가를 통해 python 파일 실행 시, pcap파일을 명령인자로 전달받도록 수정.

   - argsparser를 이용하여 -h, --help 명령을 통해 도움말을 호출할 수 있도록 수정.![도움말](/img/help.PNG)

   - 사용자가 pcap 패킷데이터를 페이지 단위로 조회할 수 있도록 메뉴 기능 구현

   - 페이지 단위 조회 시, 현재페이지, 마지막 페이지 등 사용자가 페이지이동을 편하게 할 수 있는 기능 추가 ![실행화면](/img/run4.PNG)

   - 기존의 pcap_parser.py에 선언하였던 클래스들을 각 기능별 파일로 분리함.
      - BinaryFile.py : 파일 load 관련 클래스
      - Pcap.py : Pcap관련 클래스 패키지
      - TextFormat.py : 출력 설정 관련 패키지
      - pcap_parser.py : 메인 프로그램

   - IP버전과 프로토콜은 IP_V4 와 TCP, UDP, ARP로 제한( 그 외의 패킷은 스킵한다.)

# pcap_parser V0.3 (Devel)
   - 페이지 단위 조회 시, 원하는 페이지 번호를 입력하여 이동하는 기능 추가(예정)

   - 소켓 서버 생성(통신 대기(수신쪽)) (예정)

   - 소켓 클라이언트 생성(통신 하기(송신쪽)) (예정)

   - pcap 클래스 json 변환 기능 개발 (예정)
   
# 현재 발견된 보안이슈
   - pcap_parser.py:57: High: input
   Argument 1 to this function call should be checked to ensure that it does not
   come from an untrusted source without first verifying that it contains nothing
   dangerous.

   - Analyzing BinaryFile.py
   BinaryFile.py:20: Medium: stat
   A potential TOCTOU (Time Of Check, Time Of Use) vulnerability exists.  This is
   the first line where a check has occured.
   The following line(s) contain uses that may match up with this check:
   23 (open)