# encoding: utf-8
#
# Copyright 2016, Patrick Muench
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'CIS Docker Benchmark Level 1'

only_if do
  command('docker').exist?
end

control 'cis-docker-1.1' do
  impact 1.0
  title 'Create a separate partition for containers'
  desc 'All Docker containers and their data and metadata is stored under /var/lib/docker directory. By default, /var/lib/docker would be mounted under / or /var partitions based on availability.'
  ref 'http://www.projectatomic.io/docs/docker-storage-recommendation/'

  describe mount('/var/lib/docker') do
    it { should be_mounted }
  end
end

control 'cis-docker-1.2' do
  impact 1.0
  title 'Use the updated Linux Kernel'
  desc 'Docker in daemon mode has specific kernel requirements. A 3.10 Linux kernel is the minimum requirement for Docker.'
  ref 'https://docs.docker.com/engine/installation/binaries/#check-kernel-dependencies'
  ref 'https://docs.docker.com/engine/installation/#installation-list'

  kernel_version = command('uname -r | grep -o \'^\w\.\w*\.\w*\'').stdout
  kernel_compare = Gem::Version.new('3.10') <= Gem::Version.new(kernel_version)

  describe kernel_compare do
    it { should eq true }
  end
end

control 'cis-docker-1.3' do
  impact 1.0
  title 'Harden the container host'
  desc 'Containers run on a Linux host. A container host can run one or more containers. It is of utmost importance to harden the host to mitigate host security misconfiguration'
  ref 'http://dev-sec.io'
  ref 'https://docs.docker.com/engine/security/security/'
end

control 'cis-docker-1.4' do
  impact 1.0
  title 'Remove all non-essential services from the host'
  desc 'Ensure that the host running the docker daemon is running only the essential services.'
  ref 'https://blog.docker.com/2013/08/containers-docker-how-secure-are-they/'
end

control 'cis-docker-1.5' do
  impact 1.0
  title 'Keep Docker up to date'
  desc 'The docker container solution is evolving to maturity and stability at a rapid pace. Like any other software, the vendor releases regular updates for Docker software that address security vulnerabilities, product bugs and bring in new functionality.'
  ref 'https://github.com/docker/docker/releases/latest'

  docker_server_version = command('docker version --format \'{{.Server.Version}}\'').stdout
  docker_server_compare = Gem::Version.new('1.11.1') <= Gem::Version.new(docker_server_version)

  docker_client_version = command('docker version --format \'{{.Client.Version}}\'').stdout
  docker_client_compare = Gem::Version.new('1.11.1') <= Gem::Version.new(docker_client_version)

  describe docker_server_compare do
    it { should eq true }
  end

  describe docker_client_compare do
    it { should eq true }
  end
end

control 'cis-docker-1.6' do
  impact 1.0
  title 'Only allow trusted users to control Docker daemon'
  desc 'The Docker daemon currently requires \'root\' privileges. A user added to the \'docker\' group gives him full \'root\' access rights'
  ref 'https://docs.docker.com/engine/security/security/'
  ref 'https://www.andreas-jung.com/contents/on-docker-security-docker-group-considered-harmful'
  ref 'http://www.projectatomic.io/blog/2015/08/why-we-dont-let-non-root-users-run-docker-in-centos-fedora-or-rhel/'

  describe group('docker') do
    it { should exist }
  end

  describe etc_group.where(group_name: 'docker') do
    its('users') { should include 'vagrant' }
  end
end

control 'cis-docker-1.7' do
  impact 1.0
  title 'Audit docker daemon'
  desc 'Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with \'root\' privileges. It is thus necessary to audit its activities and usage.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  describe auditd_rules do
    its(:lines) { should include('-w /usr/bin/docker -p rwxa -k docker') }
  end
end

control 'cis-docker-1.8' do
  impact 1.0
  title 'Audit Docker files and directories - /var/lib/docker'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /var/lib/docker is one such directory. It holds all the information about containers. It must be audited.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  describe auditd_rules do
    its(:lines) { should include('-w /var/lib/docker/ -p rwxa -k docker') }
  end
end

control 'cis-docker-1.9' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/docker'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/docker is one such directory. It holds various certificates and keys used for TLS communication between Docker daemon and Docker client. It must be audited.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  describe auditd_rules do
    its(:lines) { should include('-w /etc/docker/ -p rwxa -k docker') }
  end
end

control 'cis-docker-1.10' do
  impact 1.0
  title 'Audit Docker files and directories - docker.service'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. docker.service is one such file. The docker.service file might be present if the daemon parameters have been changed by an administrator. It holds various parameters for Docker daemon. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  rule = '-w ' << command('systemctl show -p FragmentPath docker.service').stdout.split('=')[1].delete("\n") << ' -p rwxa -k docker'

  describe auditd_rules do
    its(:lines) { should include(rule) }
  end
end

control 'cis-docker-1.11' do
  impact 1.0
  title 'Audit Docker files and directories - docker.service'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. docker.service is one such file. The docker.service file might be present if the daemon parameters have been changed by an administrator. It holds various parameters for Docker daemon. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  rule = '-w ' << command('systemctl show -p FragmentPath docker.socket').stdout.split('=')[1].delete("\n") << ' -p rwxa -k docker'

  describe auditd_rules do
    its(:lines) { should include(rule) }
  end
end

control 'cis-docker-1.12' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/default/docker'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/default/docker is one such file. It holds various parameters for Docker daemon. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/#daemon-configuration-file'

  only_if { os[:family] != 'centos' }
  describe auditd_rules do
    its(:lines) { should include('-w /etc/default/docker -p rwxa -k docker') }
  end
end

control 'cis-docker-1.13' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/docker/key.json'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/docker/key.json is one such file. It holds various parameters for Docker daemon. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  describe auditd_rules do
    its(:lines) { should include('-w /etc/docker/key.json -p rwxa -k docker') }
  end
end

control 'cis-docker-1.14' do
  impact 1.0
  title 'Audit Docker files and directories - /usr/bin/docker-containerd'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /usr/bin/docker-containerd is one such file. Docker now relies on containerd and runC to spawn containers. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'https://github.com/docker/docker/pull/20662'
  ref 'https://containerd.tools/'

  describe auditd_rules do
    its(:lines) { should include('-w /usr/bin/docker-containerd -p rwxa -k docker') }
  end
end

control 'cis-docker-1.15' do
  impact 1.0
  title 'Audit Docker files and directories - /usr/bin/docker-runc'
  desc 'Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /usr/bin/docker-runc is one such file. Docker now relies on containerd and runC to spawn containers. It must be audited, if applicable.'
  ref 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'https://github.com/docker/docker/pull/20662'
  ref 'https://containerd.tools/'
  ref 'https://github.com/opencontainers/runc'

  describe auditd_rules do
    its(:lines) { should include('-w /usr/bin/docker-runc -p rwxa -k docker') }
  end
end
