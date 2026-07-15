from app import create_app

app = create_app("development")

if __name__ == "__main__":
    # NOT: macOS'ta port 5000, AirPlay Receiver tarafından kullanıldığı için
    # çakışma yaşanabiliyor. Bu yüzden 5001 portunu kullanıyoruz.
    app.run(debug=True, port=5001)
    