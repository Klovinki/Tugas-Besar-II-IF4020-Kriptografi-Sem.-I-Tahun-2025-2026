# ---

**Tugas Besar II IF4020 Kriptografi \- Ijazah Ledger**

Sistem prototipe berbasis blockchain (Centralized Immutable Ledger) untuk penerbitan, penyimpanan, dan verifikasi ijazah digital secara aman menggunakan kombinasi algoritma ECDSA, SHA-256, dan AES-GCM2222.

## **1\. Daftar Fungsi Utama**

Sistem ini terbagi menjadi beberapa modul utama dengan fungsi sebagai berikut:

### **Modul Kriptografi (apps/api/crypto.py)**

* **sha256\_hex(data)**: Menghasilkan hash SHA-256 dari data dalam format hex.  
* **aes\_gcm\_encrypt(key, plaintext)**: Mengenkripsi file ijazah menggunakan AES-GCM 256-bit.  
* **ecdsa\_sign(privkey\_pem, message)**: Melakukan tanda tangan digital pada metadata transaksi menggunakan ECDSA.  
* **ecdsa\_verify(pubkey\_pem, message, sig\_hex)**: Memverifikasi keaslian tanda tangan digital.

### **Modul Ledger (apps/api/ledger.py)**

* **append\_tx(tx\_data)**: Menambahkan transaksi baru ke dalam ledger dengan mekanisme *hashing chain* (prev\_hash).  
* **verify\_chain()**: Memvalidasi seluruh rantai transaksi untuk memastikan data belum dimanipulasi.  
* **is\_revoked(cert\_id)**: Memeriksa apakah suatu ijazah telah dicabut validitasnya di dalam ledger.

### **Modul Autentikasi (apps/api/auth.py)**

* **new\_nonce()**: Membuat token sekali pakai (*nonce*) untuk mencegah *replay attack* saat login admin.  
* **verify\_nonce(nonce)**: Memvalidasi dan menghapus *nonce* yang telah digunakan.

### **Modul Aplikasi (apps/api/main.py)**

* **admin\_issue\_post()**: Alur kerja penerbitan ijazah (hashing, enkripsi, upload, dan pencatatan ke ledger).  
* **verify()**: Melakukan verifikasi ijazah dengan memeriksa integritas hash, status pencabutan, dan kepercayaan *issuer*.

## ---

**2\. Cara Menjalankan Program**

### **Prasyarat**

pastikan telah ter-install Python 3.12+ dan pip.

### **Langkah Instalasi**

1. **Clone Repositori**:  
   Bash  
   git clone \<url-repo-anda\>  
   cd \<nama-folder-repo\>

2. **Instal Dependensi**:  
   Bash  
   pip install \-r requirements.txt

3. Persiapan Kunci Admin:  
   Jalankan skrip berikut untuk menghasilkan kunci publik dan privat institusi:  
   Bash  
   python gen\_key.py

### **Menjalankan Server**

Jalankan perintah berikut di terminal:

Bash

uvicorn apps.api.main:app \--reload

Akses aplikasi melalui browser di http://127.0.0.1:8000.

## ---

**3\. Pembagian Tugas**

berikut adalah pembagian tugas:

| Nama Anggota | NIM | Tugas & Kontribusi |
| :---- | :---- | :---- |
| **Anggota 1** | 13222045 | Implementasi crypto.py (ECDSA & AES-GCM), integrasi backend FastAPI, dan pembuatan gen\_key.py. |
| **Anggota 2** | 13222119 | Pengembangan modul ledger.py (Immutable ledger & chain verification), desain skema transaksi, dan manajemen penyimpanan. |
| **Anggota 3** | 13222001 | Pengembangan antarmuka (HTML/CSS), fungsi verifikasi di frontend, penanganan fitur download, dan dokumentasi. |