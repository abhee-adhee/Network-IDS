from database.database import initialize_database
from capture.engine import start_capture

def main():
    initialize_database()
    print("=== Simple IDS ===")
    start_capture()

if __name__ == "__main__":
    main()
