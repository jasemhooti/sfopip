cat > install.sh << 'EOF'
#!/bin/bash
# =============================================
#   نصب‌کننده خودکار ICMP Spoofing Tester
#   با پشتیبانی از دو سرور (Sender + Receiver)
#   نوشته شده توسط Grok
# =============================================

echo -e "\033[1;36m"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       نصب‌کننده ICMP Spoofing Tester (نسخه فارسی)       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "\033[0m"

# بررسی دسترسی root
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31m[!] لطفاً اسکریپت را با sudo اجرا کنید: sudo bash install.sh\033[0m"
  exit 1
fi

# متغیرها
SENDER_FILE="/usr/local/bin/sender.py"
RECEIVER_FILE="/usr/local/bin/receiver.py"
SENDER_SERVICE="/etc/systemd/system/icmp-sender.service"
RECEIVER_SERVICE="/etc/systemd/system/icmp-receiver.service"

show_menu() {
    echo -e "\n\033[1;33mلطفاً گزینه مورد نظر را انتخاب کنید:\033[0m"
    echo "1) نصب در سرور ارسال‌کننده (Sender / Attacker)"
    echo "2) نصب در سرور دریافت‌کننده (Receiver / Listener)"
    echo "3) حذف کامل اسکریپت‌ها و سرویس‌ها"
    echo "4) خروج"
    echo -n "گزینه خود را وارد کنید (1-4): "
    read choice
}

install_sender() {
    echo -e "\n\033[1;32m[+] در حال نصب Sender...\033[0m"
    
    # ایجاد sender.py
    cat > "$SENDER_FILE" << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اسکریپت ارسال‌کننده ICMP Spoofing
این اسکریپت روی سرور حمله‌کننده اجرا می‌شود
"""
import socket
import struct
import time
import sys

def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def create_icmp_echo_request(seq=1):
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 12345
    data = b"X" * 56
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, seq)
    packet = header + data
    icmp_checksum = checksum(packet)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, seq)
    return header + data

def send_spoofed_icmp(src_ip, dst_ip, count=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[!] نیاز به sudo دارد!")
        sys.exit(1)

    for i in range(count):
        icmp_packet = create_icmp_echo_request(i+1)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp_packet), 54321 + i, 0, 64,
                                socket.IPPROTO_ICMP, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        sock.sendto(ip_header + icmp_packet, (dst_ip, 0))
        print(f"[✓] پکت {i+1} ارسال شد | منبع جعلی: {src_ip}")
        time.sleep(0.6)
    sock.close()
    print("[+] تمام پکت‌ها ارسال شدند.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 sender.py <IP_هدف> <IP_جعلی> [تعداد]")
        sys.exit(1)
    send_spoofed_icmp(sys.argv[2], sys.argv[1], int(sys.argv[3]) if len(sys.argv)>3 else 5)
PYEOF

    chmod +x "$SENDER_FILE"

    # ایجاد سرویس systemd برای اجرای خودکار بعد از ریبوت
    cat > "$SENDER_SERVICE" << EOF
[Unit]
Description=ICMP Spoofing Sender Service
After=network.target

[Service]
Type=oneshot
ExecStart=$SENDER_FILE TARGET_IP SPOOF_IP COUNT
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF

    # درخواست اطلاعات از کاربر
    echo -e "\n\033[1;36mاطلاعات مورد نیاز برای Sender:\033[0m"
    echo -n "IP هدف (مثلاً 8.8.8.8): "
    read TARGET_IP
    echo -n "IP جعلی (Spoof IP): "
    read SPOOF_IP
    echo -n "تعداد پکت (پیش‌فرض ۵): "
    read COUNT
    COUNT=${COUNT:-5}

    # ویرایش سرویس با مقادیر کاربر
    sed -i "s/TARGET_IP/$TARGET_IP/" "$SENDER_SERVICE"
    sed -i "s/SPOOF_IP/$SPOOF_IP/" "$SENDER_SERVICE"
    sed -i "s/COUNT/$COUNT/" "$SENDER_SERVICE"

    systemctl daemon-reload
    systemctl enable --now icmp-sender.service

    echo -e "\033[1;32m[+] نصب Sender با موفقیت انجام شد!\033[0m"
    echo "سرویس بعد از ریبوت هم به صورت خودکار اجرا می‌شود."
}

install_receiver() {
    echo -e "\n\033[1;32m[+] در حال نصب Receiver...\033[0m"
    
    cat > "$RECEIVER_FILE" << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اسکریپت دریافت‌کننده ICMP Reply
باید روی سروری اجرا شود که IP جعلی روی آن تنظیم شده
"""
import socket
import struct
import time
import sys

def listen_for_replies(timeout=30):
    print("[*] شنود ICMP Reply شروع شد...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
        start = time.time()
        count = 0
        while time.time() - start < timeout:
            try:
                packet, addr = sock.recvfrom(65535)
                ip_len = (packet[0] & 0x0F) * 4
                icmp = packet[ip_len:]
                if len(icmp) >= 8:
                    t, _, _, _, seq = struct.unpack('!BBHHH', icmp[:8])
                    if t == 0:
                        count += 1
                        print(f"[✓] دریافت جواب! از {addr[0]} | Seq: {seq}")
            except socket.timeout:
                continue
        print(f"\n[!] شنود تمام شد. تعداد جواب دریافتی: {count}")
    except Exception as e:
        print(f"[!] خطا: {e}")

if __name__ == "__main__":
    listen_for_replies(60)
PYEOF

    chmod +x "$RECEIVER_FILE"

    cat > "$RECEIVER_SERVICE" << EOF
[Unit]
Description=ICMP Spoofing Receiver Service
After=network.target

[Service]
Type=simple
ExecStart=$RECEIVER_FILE
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now icmp-receiver.service

    echo -e "\033[1;32m[+] نصب Receiver با موفقیت انجام شد!\033[0m"
    echo "این سرویس همیشه فعال است و بعد از ریبوت هم اجرا می‌شود."
    echo "ابتدا IP جعلی را روی این سرور اضافه کنید:"
    echo "مثال: sudo ip addr add 192.168.1.100/24 dev eth0"
}

remove_all() {
    echo -e "\n\033[1;31m[!] در حال حذف کامل...\033[0m"
    systemctl stop icmp-sender.service icmp-receiver.service 2>/dev/null
    systemctl disable icmp-sender.service icmp-receiver.service 2>/dev/null
    rm -f "$SENDER_FILE" "$RECEIVER_FILE" "$SENDER_SERVICE" "$RECEIVER_SERVICE"
    echo -e "\033[1;32m[+] همه چیز با موفقیت حذف شد.\033[0m"
}

# حلقه اصلی
while true; do
    show_menu
    case $choice in
        1) install_sender ;;
        2) install_receiver ;;
        3) remove_all ;;
        4) echo "خداحافظ!"; exit 0 ;;
        *) echo -e "\033[1;31mگزینه نامعتبر!\033[0m" ;;
    esac
    echo -e "\nPress Enter to continue..."
    read
done
EOF
