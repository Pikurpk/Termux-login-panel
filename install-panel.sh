#!/data/data/com.termux/files/usr/bin/bash

# Copy setup-login.sh to /usr/etc (auto login)
cp setup-login.sh $PREFIX/etc/motd

# Add startup command to bash.bashrc
echo "bash $PREFIX/etc/motd" >> $PREFIX/etc/bash.bashrc

echo ""
echo "-----------------------------------------"
echo " Lucifer Login Panel Installed Successfully!"
echo " Please RESTART Your Termux"
echo "-----------------------------------------"
