# Tiny Secondhand Shopping Platform

중고 물품 거래를 위한 Flask 기반의 웹 플랫폼입니다.  
사용자 간 실시간 채팅, 상품 등록/검색/수정/삭제, 신고 및 송금 기능을 포함하며  
보안 취약점 최소화를 목표로 설계되었습니다.

---

## ✅ 보안 목표

- **CSRF 방어**: 모든 POST 요청에 CSRF 토큰 적용 (Flask-WTF)
- **XSS 필터링**: 사용자 입력값에 대한 escape 처리 (html.escape)
- **비밀번호 해시화**: bcrypt 알고리즘을 사용하여 안전하게 저장
- **Rate Limiting**: 실시간 채팅에서 사용자당 메시지 전송 속도 제한 (초당 1회)
- **보안 헤더 설정**: Flask-Talisman을 활용한 CSP 및 X-Frame-Options 설정
- **세션 보안**: HttpOnly 및 Secure 속성 적용, 세션 만료 시간 설정
- **에러 처리**: 사용자에게 내부 정보 노출 방지, 공통 오류 페이지 처리
- **신고 남용 방지**: 사용자당 하루 최대 신고 횟수 제한 (5회)
- **감사 로그 기록**: 신고 접수 및 관리자 조치에 대한 로그 기록

---

## 📦 설치 방법

### 1. Miniconda 또는 Anaconda 설치
- 설치 링크: [https://docs.anaconda.com/free/miniconda/index.html](https://docs.anaconda.com/free/miniconda/index.html)

### 2. 저장소 클론
```bash
git clone https://github.com/unhee2/secure-coding.git
cd secure-coding
```

### 3. Conda 가상환경 생성 및 패키지 설치
```bash
conda env create -f environments.yaml
conda activate secure-coding
```

> `environments.yaml`에는 Flask, Flask-WTF, Flask-SocketIO, Flask-Talisman, bcrypt 등 필수 패키지가 포함되어 있습니다.

---

## 🚀 실행 방법

```bash
python app.py
```

서버가 5000번 포트에서 실행되며, 웹 브라우저에서 `http://localhost:5000` 으로 접속할 수 있습니다.

---

## 🌐 외부 접속 테스트 (선택 사항)

외부 네트워크에서 테스트하려면 `ngrok`을 활용해 공개 URL을 생성할 수 있습니다:

### 1. ngrok 설치 (Ubuntu 기준)
```bash
sudo snap install ngrok
```

### 2. Flask 서버 포트(5000)를 노출
```bash
ngrok http 5000
```

### 3. 출력된 HTTPS 주소 접속
```
https://xxxx-xxxx-xxxx.ngrok.io
```

---

## 🛠 기타 정보

- 최초 실행 시 `market.db` SQLite 파일이 자동 생성되며, 사용자/상품/신고/송금 테이블이 초기화됩니다.
- 관리자 계정 생성을 위한 초기 등록은 콘솔에서 직접 추가하거나, admin 생성 스크립트를 사용할 수 있습니다. 
- 운영 환경 전환 시 PostgreSQL 등 외부 DB 사용을 권장합니다.

---

## 📁 프로젝트 구조 예시

```
├── app.py
├── environments.yaml
├── templates/
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── ...
├── static/
├── market.db  ← 앱 실행 후 자동 생성
├── README.md
```

---

## 📌 GitHub 배포

본 프로젝트는 [https://github.com/unhee2/secure-coding](https://github.com/unhee2/secure-coding) 에서 공개됩니다.  
필요 시 코드 리뷰 및 개선 사항 제안은 Pull Request로 환영합니다.

---

**문서 최종 업데이트: 2025년 4월**
