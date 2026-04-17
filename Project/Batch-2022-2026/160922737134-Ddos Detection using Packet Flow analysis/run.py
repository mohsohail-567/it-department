import threading
import time
import webbrowser

from app import create_app


def main():
    app = create_app()
    url = "http://127.0.0.1:5000"

    def open_browser():
        time.sleep(1.5)
        try:
            webbrowser.open(url)
        except Exception as e:
            print("[BROWSER OPEN ERROR]", e)

    threading.Thread(target=open_browser, daemon=True).start()

    print("\nStarting PacketFlow Guard...")
    print(f"Opening browser at {url}\n")

    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()