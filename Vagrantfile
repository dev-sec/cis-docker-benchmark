# encoding: utf-8

# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  config.vm.define :ubuntu1604 do |ubuntu1604|
    ubuntu1604.vm.box = 'ubuntu/xenial64' # https://atlas.hashicorp.com/ubuntu/boxes/xenial64
    # install docker
    ubuntu1604.vm.provision :shell, inline: 'curl -fsSL https://get.docker.com/ | sh'
    # add vagrant user to docker group
    ubuntu1604.vm.provision :shell, inline: 'usermod -aG docker ubuntu'
    # reload and restart docker daemon
    ubuntu1604.vm.provision :shell, inline: 'systemctl daemon-reload'
    ubuntu1604.vm.provision :shell, inline: 'systemctl restart docker.service'
    # start one docker container
    ubuntu1604.vm.provision :shell, inline: 'docker run -d ubuntu /bin/bash -c "while true; do echo hello world; sleep 1; done"'
    ubuntu1604.vm.network 'private_network', ip: '192.168.34.101'
  end

  config.vm.define :centos7 do |centos7|
    centos7.vm.box = 'centos/7' # https://atlas.hashicorp.com/centos/boxes/7
    # install docker
    centos7.vm.provision :shell, inline: 'curl -fsSL https://get.docker.com/ | sh'
    # add vagrant user to docker group
    centos7.vm.provision :shell, inline: 'usermod -aG docker vagrant'
    # reload and restart docker daemon
    centos7.vm.provision :shell, inline: 'systemctl daemon-reload'
    centos7.vm.provision :shell, inline: 'systemctl restart docker.service'
    # start one docker container
    centos7.vm.provision :shell, inline: 'docker run -d ubuntu /bin/bash -c "while true; do echo hello world; sleep 1; done"'
    centos7.vm.network 'private_network', ip: '192.168.34.102'
  end

  config.vm.define :debian8 do |debian8|
    debian8.vm.box = 'debian/jessie64' # https://atlas.hashicorp.com/debian/boxes/jessie64/
    # install curl
    debian8.vm.provision :shell, inline: 'apt-get update'
    debian8.vm.provision :shell, inline: 'apt-get install -y curl'
    # install docker
    debian8.vm.provision :shell, inline: 'curl -fsSL https://get.docker.com/ | sh'
    # add vagrant user to docker group
    debian8.vm.provision :shell, inline: 'usermod -aG docker vagrant'
    # reload and restart docker daemon
    debian8.vm.provision :shell, inline: 'systemctl daemon-reload'
    debian8.vm.provision :shell, inline: 'systemctl restart docker.service'
    # start one docker container
    debian8.vm.provision :shell, inline: 'docker run -d ubuntu /bin/bash -c "while true; do echo hello world; sleep 1; done"'
    debian8.vm.network 'private_network', ip: '192.168.34.103'
  end
end
