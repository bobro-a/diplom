sudo systemctl stop connman
sudo systemctl disable connman 
sudo systemctl unmask NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
sudo systemctl enable NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
sudo systemctl start NetworkManager systemd-networkd systemd-networkd.socket systemd-resolved
