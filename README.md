# NACSystem - Network Access Control (AAA Mimarisi)

Kurumsal ağlara erişimi yöneten, **Authentication (Kimlik Dogrulama)**, **Authorization (Yetkilendirme)** ve **Accounting (Muhasebe/Kayit)** islemlerini uygulayan bir Network Access Control sistemidir.

## Sistem Mimarisi

```
                          +-----------------+
  Kullanici / Cihaz ----->| FreeRADIUS 3.2  |-----> UDP 1812 (Auth)
  (radtest / switch)      | (RADIUS Server) |-----> UDP 1813 (Acct)
                          +--------+--------+
                                   |
                           rlm_rest modulu
                          (HTTP POST istekleri)
                                   |
                          +--------v--------+
                          | FastAPI (Python) |-----> TCP 8000
                          | Policy Engine    |       /auth, /authorize
                          +--+----------+---+       /accounting, /dashboard
                             |          |
                    +--------v--+  +----v------+
                    | PostgreSQL|  |   Redis    |
                    | (Kalici   |  | (Aktif     |
                    |  Veri)    |  |  Oturum    |
                    +-----------+  |  Onbellegi)|
                                   +-----------+
```

### Kullanilan Teknolojiler

| Servis | Imaj | Port | Gorev |
|--------|------|------|-------|
| FreeRADIUS 3.2 | `freeradius/freeradius-server:latest-3.2` | 1812/udp, 1813/udp | RADIUS protokolu ile kimlik dogrulama ve muhasebe |
| PostgreSQL 18 | `postgres:18-alpine` | 5432 | Kullanici, grup, VLAN ve oturum kayitlarini saklar |
| Redis 8 | `redis:8-alpine` | 6379 | Aktif oturumlari bellekte onbellegeler |
| FastAPI | `python:3.13-slim` | 8000 | Politika motoru — FreeRADIUS'un karar mekanizmasi |

## Kurulum

### Gereksinimler

- Docker & Docker Compose (v2+)
- Git

### Adim 1: Projeyi Klonlayin

```bash
git clone <repo-url>
cd NACSystem
```

### Adim 2: Ortam Degiskenlerini Ayarlayin

```bash
cp .env.example .env
```

`.env` dosyasini acin ve sifreleri degistirin:

```env
POSTGRES_USER=nac_admin
POSTGRES_PASSWORD=guclu_bir_sifre_girin
POSTGRES_DB=nac_db
REDIS_PASSWORD=guclu_bir_redis_sifresi
DATABASE_URL=postgresql://nac_admin:guclu_bir_sifre_girin@postgres:5432/nac_db
REDIS_URL=redis://:guclu_bir_redis_sifresi@redis:6379/0
```

> **ONEMLI:** `.env` dosyasi hassas bilgiler icerir. Git'e **asla** commit etmeyin. `.gitignore` dosyasinda zaten haric tutulmustur.

### Adim 3: Sistemi Baslatin

```bash
docker compose up -d --build
```

Tum servislerin "healthy" (saglikli) durumda oldugundan emin olun:

```bash
docker ps
```

Beklenen cikti:

```
nac-postgres     ... (healthy)
nac-redis        ... (healthy)
nac-freeradius   ... (healthy)
nac-api          ... (healthy)
```

## Test Komutlari

Asagidaki tum komutlar `nac-freeradius` container'i icinde calistirilir.

### 1. PAP Kimlik Dogrulama (Authentication)

Kullanici adi ve sifre ile test:

```bash
docker exec -it nac-freeradius radtest testuser testpass123 localhost 0 testing123
```

**Beklenen sonuc:** `Access-Accept`

### 2. MAC Authentication Bypass (MAB)

Yazici, IP telefon gibi 802.1X desteklemeyen cihazlar icin:

```bash
docker exec -it nac-freeradius bash -c "echo 'User-Name=00:11:22:33:44:55
User-Password=00:11:22:33:44:55
Calling-Station-Id=00:11:22:33:44:55' | radclient 127.0.0.1:1812 auth testing123"
```

**Beklenen sonuc:** `Access-Accept`

### 3. Accounting - Oturum Baslat (Start)

```bash
docker exec -it nac-freeradius bash -c "echo 'User-Name=testuser
Acct-Status-Type=Start
Acct-Session-Id=session001
Acct-Unique-Session-Id=unique001
NAS-IP-Address=10.0.0.1
Calling-Station-Id=AA:BB:CC:DD:EE:FF
Framed-IP-Address=192.168.1.100' | radclient 127.0.0.1:1813 acct testing123"
```

**Beklenen sonuc:** `Accounting-Response`

### 4. Accounting - Oturum Bitir (Stop)

```bash
docker exec -it nac-freeradius bash -c "echo 'User-Name=testuser
Acct-Status-Type=Stop
Acct-Session-Id=session001
Acct-Unique-Session-Id=unique-stop-001
NAS-IP-Address=10.0.0.1
Acct-Session-Time=300
Acct-Input-Octets=1024
Acct-Output-Octets=2048
Acct-Terminate-Cause=User-Request' | radclient 127.0.0.1:1813 acct testing123"
```

**Beklenen sonuc:** `Accounting-Response`

### 5. Dogrulama Komutlari

Accounting verilerinin PostgreSQL'e yazildigini dogrulayin:

```bash
docker exec -it nac-postgres psql -U nac_admin -d nac_db -c "SELECT username, acctstarttime, acctstoptime FROM radacct;"
```

Aktif oturumlari Redis'ten kontrol edin:

```bash
curl http://localhost:8000/sessions/active
```

## Bonus Ozellikler (+%5)

### Izleme Paneli (Monitoring Dashboard)

Tarayicida acin: **http://localhost:8000/dashboard**

Dashboard sunlari gosterir:
- Aktif oturum sayisi (Redis'ten canli)
- Kayitli kullanici ve cihaz listesi (PostgreSQL'den)
- Son 20 accounting kaydi (oturum baslangic/bitis)
- Sistem durumu ozet kartlari

### Unit Testler (Pytest)

Testleri container icinde calistirin:

```bash
docker exec -it nac-api pytest test_main.py -v
```

5 test mevcuttur:

| Test | Dogruladigi Sey |
|------|----------------|
| `test_auth_accepts_valid_password` | Dogru sifre → HTTP 204 (Accept) |
| `test_auth_rejects_wrong_password` | Yanlis sifre → HTTP 401 (Reject) |
| `test_authorize_returns_vlan_attributes` | VLAN atamasi icin dogru JSON yapisi |
| `test_accounting_start_returns_204` | Oturum kaydinin DB ve Redis'e yazilmasi |
| `test_health_check` | Tum servislerin bagli oldugu |

## API Endpointleri

| Metod | Yol | Aciklama |
|-------|-----|----------|
| POST | `/auth` | Kimlik dogrulama (kullanici+sifre veya MAB) |
| POST | `/authorize` | Yetkilendirme (grup ve VLAN politikasi) |
| POST | `/accounting` | Muhasebe (oturum baslat/guncelle/bitir) |
| GET | `/users` | Kayitli kullanici listesi |
| GET | `/sessions/active` | Aktif oturumlar (Redis'ten) |
| GET | `/dashboard` | HTML izleme paneli |
| GET | `/health` | Sistem saglik kontrolu |

## Veritabani Semasi

```
radcheck        → Kullanici kimlik bilgileri (sifre hash'leri)
radreply        → Kullaniciya ozel RADIUS yanit ozellikleri
radusergroup    → Kullanici-grup eslemesi (testuser → employee)
radgroupreply   → Gruba ozel VLAN atamalari (employee → VLAN 20)
radacct         → Oturum kayitlari (baslangic, bitis, sure, trafik)
```

### VLAN Atamalari

| Grup | VLAN | Ag |
|------|------|----|
| admin | 10 | Yonetim agi |
| employee | 20 | Kurumsal ag |
| guest | 30 | Kisitli internet |

## Guvenlik Uygulamalari

- Sifreler **SHA-256 hash** olarak saklanir (plaintext asla yazilmaz)
- Ortam degiskenleri `.env` dosyasindan okunur, kod icinde hardcoded degildir
- FreeRADIUS yapilandirma dosyalari **640** izinleriyle korunur
- Redis sifre korumasina sahiptir (`--requirepass`)
- SQL sorgulari parameterized olarak yazilmistir (SQL injection korunmasi)

## Proje Dizin Yapisi

```
NACSystem/
├── docker-compose.yml          # Tum servislerin orkestasyonu
├── .env.example                # Ornek ortam degiskenleri
├── .gitignore
├── README.md
├── api/
│   ├── Dockerfile              # FastAPI container tanimi
│   ├── requirements.txt        # Python bagimliklar
│   ├── main.py                 # Policy Engine (7 endpoint)
│   ├── test_main.py            # Unit testler (pytest)
│   └── templates/
│       └── dashboard.html      # Izleme paneli HTML
├── freeradius/
│   ├── Dockerfile              # FreeRADIUS container tanimi
│   ├── clients.conf            # RADIUS istemci tanimlari
│   ├── mods-enabled/
│   │   └── rest                # rlm_rest modul yapilandirmasi
│   └── sites-enabled/
│       └── default             # Sanal sunucu yapilandirmasi
└── postgres/
    └── init.sql                # Veritabani semasi ve test verileri
```
