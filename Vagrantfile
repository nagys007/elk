# -*- mode: ruby -*-
# vi: set ft=ruby :

ip = "192.168.33.90"

$done = <<SHELL
SHELL

$params = <<SHELL
#
### https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04
#
export KIBANA_ADMIN=$1
echo KIBANA_ADMIN=$KIBANA_ADMIN
export KIBANA_PASSWORD=$2
echo KIBANA_PASSWORD=$KIBANA_PASSWORD
SHELL

$homedir = <<SHELL
export HOME_VAGRANT=$(pwd)
echo HOME_VAGRANT=$HOME_VAGRANT
pwd
ls -l
SHELL

#
### Java 8
#
$java8 = <<SHELL
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get -qq update
# prepare unattended installation
echo "debconf shared/accepted-oracle-license-v1-1 select true" | sudo /usr/bin/debconf-set-selections
echo "debconf shared/accepted-oracle-license-v1-1 seen true" | sudo /usr/bin/debconf-set-selections
export DEBIAN_FRONTEND=noninteractive
sudo apt-get -y install oracle-java8-installer
SHELL

#
### Elastic Search
#
$elasticsearch = <<SHELL
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee /etc/apt/sources.list.d/elasticsearch-2.x.list
sudo apt-get -qq update
sudo apt-get -y install elasticsearch
sudo grep network.host /etc/elasticsearch/elasticsearch.yml
sudo sed 's/# network.host: 192.168.0.1/network.host: localhost/g' -i /etc/elasticsearch/elasticsearch.yml
sudo grep network.host /etc/elasticsearch/elasticsearch.yml
sudo service elasticsearch restart
sudo update-rc.d elasticsearch defaults 95 10
SHELL

#
### Kibana
#
$kibana = <<SHELL
echo "deb https://packages.elastic.co/kibana/4.4/debian stable main" | sudo tee /etc/apt/sources.list.d/kibana-4.4.x.list
sudo apt-get -qq update
sudo apt-get -y install kibana
grep server.host /opt/kibana/config/kibana.yml
sudo sed 's/# server.host: "0.0.0.0"/server.host: "localhost"/g' -i /opt/kibana/config/kibana.yml
grep server.host /opt/kibana/config/kibana.yml
sudo service kibana restart
sudo update-rc.d kibana defaults 96 9
SHELL

#
### Nginx
#
$nginx = <<SHELL
sudo apt-get -y install nginx apache2-utils
export KIBANA_ADMIN=$1
echo KIBANA_ADMIN=$KIBANA_ADMIN
export KIBANA_PASSWORD=$2
echo KIBANA_PASSWORD=$KIBANA_PASSWORD
sudo htpasswd -c -b /etc/nginx/htpasswd.users $KIBANA_ADMIN $KIBANA_PASSWORD
sudo cp -n /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup
# cd $HOME_VAGRANT
sudo cp -b nginx_default.conf /etc/nginx/sites-available/default
sudo service nginx restart
SHELL

#
### Logstash
#
$logstash = <<SHELL
echo 'deb https://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list
sudo apt-get -qq update
sudo apt-get -y install logstash
SHELL

#
# SSL certificates
#
$ssl_cert = <<SHELL
export IP_ADDRESS=$1
echo IP_ADDRESS=$IP_ADDRESS
export IP_ADDRESS=$(ifconfig eth1 | grep "inet addr" | awk 'BEGIN { FS = "[ :]+" }{print $4}')
echo IP_ADDRESS=$IP_ADDRESS
sudo mkdir -p -v /etc/pki/tls/certs
[ -d /etc/pki/tls/private ] || sudo mkdir -p -v /etc/pki/tls/private
grep 'subjectAltName' /etc/ssl/openssl.cnf
sudo sed "/subjectAltName = /d" -i /etc/ssl/openssl.cnf
sudo sed "s/\\[ v3_ca ]/[ v3_ca ]\\nsubjectAltName = IP: $IP_ADDRESS/" -i /etc/ssl/openssl.cnf
grep 'subjectAltName' /etc/ssl/openssl.cnf
cd /etc/pki/tls
sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 \
  -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt >~/openssl-req.stdall 2>&1
cat ~/openssl-req.stdall
SHELL

#
# Logstash config
#
$logstash_config = <<SHELL
# cd $HOME_VAGRANT
sudo cp -b -v logstash_02-beats-input.conf \
   logstash_10-syslog-filter.conf \
   logstash_30-elasticsearch-output.conf \
   /etc/logstash/conf.d
sudo service logstash configtest
sudo service logstash restart
SHELL
#
# Sample Kibana Dashboard
#
$dashboard = <<SHELL
# cd $HOME_VAGRANT
rm -f -v beats-dashboards-*.zip
curl --silent -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
sudo apt-get -y install unzip
sudo unzip -q -o beats-dashboards-*.zip
cd beats-dashboards-*
sudo sed 's/CURL=curl/CURL="curl --silent"/' -i ./load.sh
# cat ./load.sh
sudo ./load.sh -url "http://localhost:9200/" >load.stdout
SHELL

#
# filebeat
#
$filebeat = <<SHELL
# download and install index template in ES, first
# cd $HOME_VAGRANT
curl --silent -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
# head filebeat-index-template.json
curl --silent -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json
# and now install filebeat (should be on client, but we use the ELK server here)
echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee /etc/apt/sources.list.d/beats.list
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get -qq update
sudo apt-get -y install filebeat
#
sudo cp -n -v /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup
sudo cp -b -v filebeat_filebeat.yml /etc/filebeat/filebeat.yml
#
# grep "\\- /var/log" /etc/filebeat/filebeat.yml
# sudo sed "s|- /var/log/\\*.log|- /var/log/auth.log\\n        - /var/log/syslog\\n#        - /var/log/\\*.log|" -i /etc/filebeat/filebeat.yml
# grep "\\- /var/log" /etc/filebeat/filebeat.yml
# grep "document_type:" /etc/filebeat/filebeat.yml
# sudo sed "s/#document_type: log/document_type: syslog/" -i /etc/filebeat/filebeat.yml
# grep "document_type:" /etc/filebeat/filebeat.yml
# comment elasticsearch (complete section)
# grep "elasticsearch:" /etc/filebeat/filebeat.yml
# sudo sed "s/  elasticsearch:/  # elasticsearch:/" -i /etc/filebeat/filebeat.yml
# grep "elasticsearch:" /etc/filebeat/filebeat.yml
# uncomment logstash + additional config changes (see guide)
# grep "logstash:" /etc/filebeat/filebeat.yml
# sudo sed "s/#logstash:/logstash:/" -i /etc/filebeat/filebeat.yml
# grep "logstash:" /etc/filebeat/filebeat.yml
# uncomment certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
# grep "certificate_authorities:" /etc/filebeat/filebeat.yml
# sudo sed 's|#certificate_authorities: ["/etc/pki/root/ca.pem"]|#certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]|' -i /etc/filebeat/filebeat.yml
# sudo sed 's|#certificate_authorities: ["/etc/pki/root/ca.pem"]|certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]|' -i /etc/filebeat/filebeat.yml
# grep "certificate_authorities:" /etc/filebeat/filebeat.yml
# sudo vi /etc/filebeat/filebeat.yml
grep "hosts:" /etc/filebeat/filebeat.yml
export IP_ADDRESS=$(ifconfig eth1 | grep "inet addr" | awk 'BEGIN { FS = "[ :]+" }{print $4}')
echo IP_ADDRESS=$IP_ADDRESS
sudo sed "s/hosts: \\[\\"localhost:5044\\"]/hosts: \\[\\"$IP_ADDRESS:5044\\"]/" -i /etc/filebeat/filebeat.yml
grep "hosts:" /etc/filebeat/filebeat.yml
#
sudo service filebeat restart
sudo update-rc.d filebeat defaults 95 10
SHELL

#
### topbeat
#
# https://www.digitalocean.com/community/tutorials/how-to-gather-infrastructure-metrics-with-topbeat-and-elk-on-ubuntu-14-04
$topbeat = <<SHELL
# download and install index template in ES, first
# cd $HOME_VAGRANT
curl --silent -O https://raw.githubusercontent.com/elastic/topbeat/master/etc/topbeat.template.json
head topbeat.template.json
curl --silent -XPUT 'http://localhost:9200/_template/topbeat' -d@topbeat.template.json
# and now install topbeat (should be on client, but we use the ELK server here)
echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee /etc/apt/sources.list.d/beats.list
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get -qq update
sudo apt-get -y install topbeat
#
sudo cp -n -v /etc/topbeat/topbeat.yml /etc/topbeat/topbeat.yml.backup
sudo cp -b -v topbeat_topbeat.yml /etc/topbeat/topbeat.yml
# sudo vi /etc/topbeat/topbeat.yml
# comment elasticsearch (complete section)
# uncomment logstash + additional config changes (see guide)
# uncomment certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
grep "hosts:" /etc/topbeat/topbeat.yml
export IP_ADDRESS=$(ifconfig eth1 | grep "inet addr" | awk 'BEGIN { FS = "[ :]+" }{print $4}')
echo IP_ADDRESS=$IP_ADDRESS
sudo sed "s/hosts: \\[\\"localhost:5044\\"]/hosts: \\[\\"$IP_ADDRESS:5044\\"]/" -i /etc/topbeat/topbeat.yml
grep "hosts:" /etc/topbeat/topbeat.yml
#
sudo service topbeat restart
sudo update-rc.d topbeat defaults 95 10
SHELL


# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "ubuntu/trusty64"

  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  config.vm.network "private_network", ip: ip

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
    vb.memory = "4096"
    vb.cpus = 2
  end
  #
  # View the documentation for the provider you are using for more
  # information on available options.

  # Define a Vagrant Push strategy for pushing to Atlas. Other push strategies
  # such as FTP and Heroku are also available. See the documentation at
  # https://docs.vagrantup.com/v2/push/atlas.html for more information.
  # config.push.define "atlas" do |push|
  #   push.app = "YOUR_ATLAS_USERNAME/YOUR_APPLICATION_NAME"
  # end

   config.vm.provision "file", source: "nginx.conf", destination: "nginx_default.conf"

   config.vm.provision "file", source: "logstash_02-beats-input.conf", destination: "logstash_02-beats-input.conf"
   config.vm.provision "file", source: "logstash_10-syslog-filter.conf", destination: "logstash_10-syslog-filter.conf"
   config.vm.provision "file", source: "logstash_30-elasticsearch-output.conf", destination: "logstash_30-elasticsearch-output.conf"

   config.vm.provision "file", source: "filebeat_filebeat.yml", destination: "filebeat_filebeat.yml"
   config.vm.provision "file", source: "topbeat_topbeat.yml", destination: "topbeat_topbeat.yml"

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
  #config.vm.provision "shell", inline: $homedir
  #config.vm.provision "shell" do |s|
    #s.inline = $params
    #s.args = ["kibanaadmin", "kibana_passwd"]
  #end
  #
  # config.vm.provision "shell", inline: $java8
  # config.vm.provision "shell", inline: $elasticsearch
  # config.vm.provision "shell", inline: $kibana
  # config.vm.provision "shell", inline: $nginx, args: ["kibanaadmin", "kibana_passwd"]
  # config.vm.provision "shell", inline: $logstash
  # config.vm.provision "shell", inline: $ssl_cert, args: [ip]
  # config.vm.provision "shell", inline: $logstash_config
  # config.vm.provision "shell", inline: $dashboard
   config.vm.provision "shell", inline: $filebeat, args: [ip]
   config.vm.provision "shell", inline: $topbeat, args: [ip]
  #
  # config.vm.provision "shell", inline: $done
end
