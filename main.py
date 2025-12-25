# File utama menjalankan API server yang ada di file api.py

import uvicorn

def main():
	uvicorn.run("api:app", host="0.0.0.0", port=8080, reload=True)

if __name__ == "__main__":
    main()
