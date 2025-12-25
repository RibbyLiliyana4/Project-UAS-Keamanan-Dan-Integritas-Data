# KID Project
Project ini mensimulasikan layanan security server sederhana dalam bahasa Python.

# Instalasi
1.  Pasang uv from [situs resmi](https://docs.astral.sh/uv/getting-started/installation/).
2.  Persipakan project ini dengan melakukan sinkronisasi dependensi. Ketik `uv sync` pada terminal di lokasi project ini berada. Perintah ini akan membuat sebuah virtual environment `.venv` (hidden) pada root folder, lalu memasang libraries yang dibutuhkan.
3.  Untuk menjalankan server FastAPI, ketik perintah:
```
uv run main.py
```
Untuk penggunaan lainnya, lihat bab Penggunaan.

# Petunjuk Penggunaan dan Informasi API keseluruhan
1.  Menjalankan server FastAPI
```
uv run main.py
```
2.  Mengakses antarmuka API (seperti [Postman](https://www.postman.com/) atau [Bruno](https://www.usebruno.com/)) dapat melalui platform bawaan FastAPI, yaitu `SwaggerAPI` dengan cara:
```
http://localhost:8080/docs
```
3.  Laman `SwaggerAPI` (http://localhost:8080/docs) akan menampilkan seluruh fungsi-fungsi API yang telah anda buat dalam file `api.py`.
    -   Klik pada fungsi yang akan diakses.
    -   Klik `Try it out`
    -   Lengkapi formulir (parameters fungsi) yang dibutuhkan.
    -   Klik `Execute` untuk melakukan "submission".