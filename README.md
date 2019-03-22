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
- conda install 

4. # IDE 실행
- activate py37
- spyder 엔터
- 굳이 py37 환경을 activate 하는 이유는 spyder IDE에서 py37 환경을 이용하기 위해서이다.

5. # 소스 파일 실행
- git을 클론한다.
- '4' 를 진행하여 IDE를 실행한다.
- spyder 에서 git을 클론한 폴더의 경로에 존재하는 pcap_parser.py 를 불러온다
- 실행해본다.(f5)
- ![실행사진](/img/run1.PNG)

6. # 현재까지 진행된 척도
- Binary 파일을 다루기 위한 클래스 생성
- Pcap binary 파일의 Global Header 분석
- Pcap Packet Header의 분석
- 각 Header별 클래스 생성

7. # 추후 진행해야되는 사항
- packet header 다음에 나오게될 packer body 부분의 분석 필요
- 파일 read 및 write, packet 분석 시 발생할 수 있는 Exception 분석
- 각 Exception을 캐치하기 위한 알고리즘 분석
- 각 클래스들을 패키지화 하여야함


8. # REFERENCE
- [용팔이세상](https://dragon82.tistory.com/10)
- [Hison.me](https://hiseon.me/2018/01/30/pcap-basic-example/)
- [ehclub.co.kr](https://ehclub.co.kr/2548)
- [pcak wiki](https://en.wikipedia.org/wiki/Pcap)