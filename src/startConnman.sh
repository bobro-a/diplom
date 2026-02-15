sudo systemctl stop NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
sudo systemctl disable NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
sudo systemctl mask NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
sudo systemctl enable connman
sudo systemctl restart connman
