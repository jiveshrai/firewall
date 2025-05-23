from firewall_engine import process_packet
from netfilterqueue import NetfilterQueue

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)

    print("[*] Real-Time Firewall Started. Press Ctrl+C to stop.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Firewall Stopped.")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
