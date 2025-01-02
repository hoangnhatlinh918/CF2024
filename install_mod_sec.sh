#log bot: docker-compose logs -f bot  
#
##may can phai thong internet, check version nginx (nginx -v) va fill xuong duoi (3 location) + chay 'apt-get update' truoc
####LUU Y: CAN DOWNLOAD FILE splunkclouduf.spl va copy vao /root/
#tail -f /opt/modsecurity/var/log/debug.log
# find /var/log/modsec/20241017/ -type f -exec cat {} + | grep 403
#nginx -t
#
#exclude 1 ip:         SecRule REMOTE_ADDR "@contains 127.0.0.1" "id:1,phase:1,allow,ctl:ruleEngine=Off"
#
#
#SecRule ARGS "@contains L2ZsYQ" "id:1001,phase:1,deny,msg:"Block encode base64 /flag/"
#SecRule ARGS "@contains ZmxhZw" "id:1002,phase:1,deny,msg:"Block encode base64 /flag/"
#SecRule ARGS "@contains bGFnLw" "id:1003,phase:1,deny,msg:"Block encode base64 /flag/"
#SecRule ARGS:f "@contains /flag" "id:1004,phase:2,t:base64Decode,t:lowercase,deny,msg:'Request contains /flag'"
#SecRule REQUEST_HEADERS:X-File-Name ".*\.php" "id:1005,phase:2,t:lowercase,deny,status:403,log,msg:'PHP extension in X-File-Name header'"
#SecRule REQUEST_URI|REQUEST_HEADERS|REQUEST_BODY "@contains /flag/flag" "id:1006,phase:2,deny,msg:'Block getting flag"
#
#
#SecRule ARGS "@contains script" "id:2001,phase:2,t:lowercase,deny,msg:'Block keyword script in arguments'"
#SecRule ARGS "@contains script" "id:2002,phase:2,t:base64Decode,t:lowercase,deny,msg:'Block keyword script after base64 decoding'"
#
#combine multi condition
#SecRule REQUEST_URI "@contains /vulnerabilities/exec/" "id:1004,phase:2,deny,t:none,log,msg:'abc',chain"
#SecRule REQUEST_BODY "@rx ^[a-zA-Z]*$" "t:none"
#
#
#####config splunk: https://docs.splunk.com/Documentation/Forwarder/9.3.1/Forwarder/Configuretheuniversalforwarder


#! /bin/bash
apt-get update
apt-get install libtool autoconf build-essential libpcre3-dev zlib1g-dev libssl-dev libxml2-dev libgeoip-dev liblmdb-dev libyajl-dev libcurl4-openssl-dev pkgconf libxslt1-dev libgd-dev automake
#Download Source ModSecurity to get config
cd /usr/local/src
git clone --depth 100 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
git submodule init
git submodule update

#Compile ModSecurity and install
# Generate configure file
sh build.sh
# Pre compilation step. Checks for dependencies
./configure
# Compiles the source code
make
# Installs the Libmodsecurity to **/usr/local/modsecurity/lib/libmodsecurity.so**
make install

mkdir /usr/local/src/cpg
cd /usr/local/src/cpg
#Make sure to change versoin number match it with your local Nginx server version
wget http://nginx.org/download/nginx-1.24.0.tar.gz
# Extract the downloaded source code...make sure to use the corerct Nginx version number that you have downloaded 
tar -xvzf nginx-1.24.0.tar.gz
# Download the source code for ModSecurity-nginx connector
git clone https://github.com/SpiderLabs/ModSecurity-nginx

# Compile the Nginx...make sure to use the corerct Nginx version number that you have downloaded 
cd nginx-1.24.0
./configure --with-compat --with-openssl=/usr/include/openssl/ --add-dynamic-module=/usr/local/src/cpg/ModSecurity-nginx

make modules

mkdir /etc/nginx/modules/
cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules


#Enable ModSecurity in nginx.conf
sed -i '1i\load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf
sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/modsec-config.conf;' /etc/nginx/nginx.conf

#Create Directory and Files for ModSecurity 3 and config
sudo mkdir /var/log/modsec/
sudo chmod 777 /var/log/modsec/
sudo mkdir /etc/nginx/modsec/
sudo cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditLogParts ABIJDEFHZ/SecAuditLogParts ABCEFHJKZ/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditEngine RelevantOnly/SecAuditEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditLogType Serial/#SecAuditLogType Serial/' /etc/nginx/modsec/modsecurity.conf
sed -i 's#^SecAuditLog /var/log/modsec_audit.log#SecAuditLogFormat JSON\nSecAuditLogType Concurrent\nSecAuditLogStorageDir /var/log/modsec/\nSecAuditLogFileMode 0777\nSecAuditLogDirMode 0777#' /etc/nginx/modsec/modsecurity.conf

#Create modsec-config.conf File
echo "Include /etc/nginx/modsec/modsecurity.conf" > /etc/nginx/modsec/modsec-config.conf
sudo cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/

#Install OWASP Core Rule Set for ModSecurity 3
cd /etc/nginx/modsec
wget https://github.com/coreruleset/coreruleset/archive/refs/tags/nightly.tar.gz
tar -xvf nightly.tar.gz
sudo cp /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf.example /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf
#echo "Include /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf" >> /etc/nginx/modsec/modsec-config.conf
#echo "Include /etc/nginx/modsec/coreruleset-nightly/rules/*.conf" >> /etc/nginx/modsec/modsec-config.conf
#service nginx restart


#download splunk enterprise
####LUU Y: CAN DOWNLOAD FILE splunkclouduf.spl va copy vao /root/
wget -O splunkforwarder-9.3.1-0b8d769cb912-linux-2.6-amd64.deb "https://download.splunk.com/products/universalforwarder/releases/9.3.1/linux/splunkforwarder-9.3.1-0b8d769cb912-linux-2.6-amd64.deb"
dpkg -i splunkforwarder-9.3.1-0b8d769cb912-linux-2.6-amd64.deb
cd /opt/splunkforwarder/bin/
/opt/splunkforwarder/bin/splunk start --accept-license
/opt/splunkforwarder/bin/splunk install app /root/splunkclouduf.spl -auth sc_admin:E5e5e5@52
/opt/splunkforwarder/bin/splunk add forward-server prd-p-9n2tf.splunkcloud.com:9997 -auth sc_admin:E5e5e5@52
/opt/splunkforwarder/bin/splunk add monitor -auth sc_admin:E5e5e5@52 /var/log/modsec/
#/opt/splunkforwarder/bin/splunk add monitor -auth sc_admin:E5e5e5@52 /var/log/nginx/error.log
/opt/splunkforwarder/bin/splunk restart

#neu khong restart duoc thi dung lenh kill -9 <PID>
#source="/var/log/nginx/access.log" NOT "http://host.docker.internal" AND status="200" | where like(uri, "%img%")
#source="/var/log/nginx/access.log" NOT "http://host.docker.internal"| stats count by clientip
#
#
#
#

#echo "[monitor:///var/log/modsec/]
#disabled = false
#index = modsecurity
#sourcetype = json" | sudo tee -a /opt/splunkforwarder/etc/system/local/inputs.conf


