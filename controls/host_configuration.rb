# encoding: utf-8
# frozen_string_literal: true

# Copyright 2016, Patrick Muench
# Copyright 2017, Christoph Hartmann
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

title 'Host Configuration'

TRUSTED_USER = attribute('trusted_user')
MANAGEABLE_CONTAINER_NUMBER = attribute('managable_container_number')
BENCHMARK_VERSION = attribute('benchmark_version')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'host-1.1' do
  impact 1.0
  title 'Create a separate partition for containers'
  desc 'All Docker containers and their data and metadata is stored under /var/lib/docker directory. By default, /var/lib/docker would be mounted under / or /var partitions based on availability.

  Rationale: Docker depends on /var/lib/docker as the default directory where all Docker related files, including the images, are stored. This directory might fill up fast and soon Docker and the host could become unusable. So, it is advisable to create a separate partition (logical volume) for storing Docker files.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.1'
  tag 'cis-docker-1.13.0': '1.1'
  tag 'level:1'
  ref 'Docker storage recommendation', url: 'http://www.projectatomic.io/docs/docker-storage-recommendation/'

  describe mount('/var/lib/docker') do
    it { should be_mounted }
  end
end

control 'host-1.2' do
  impact 1.0
  title 'Use the updated Linux Kernel'
  desc 'Docker in daemon mode has specific kernel requirements. A 3.10 Linux kernel is the minimum requirement for Docker.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.2'
  tag 'level:1'
  ref 'Check kernel dependencies', url: 'https://docs.docker.com/engine/installation/binaries/#check-kernel-dependencies'
  ref 'Installation list', url: 'https://docs.docker.com/engine/installation/#installation-list'

  only_if { os.linux? }
  kernel_version = command('uname -r | grep -o \'^\w\.\w*\.\w*\'').stdout
  kernel_compare = Gem::Version.new('3.10') <= Gem::Version.new(kernel_version)
  describe kernel_compare do
    it { should eq true }
  end
  only_if { BENCHMARK_VERSION == '1.12.0' }
end

control 'host-1.3' do
  impact 1.0
  title 'Harden the container host'
  desc 'Containers run on a Linux host. A container host can run one or more containers. It is of utmost importance to harden the host to mitigate host security misconfiguration.

  Rationale: You should follow infrastructure security best practices and harden your host OS. Keeping the host system hardened would ensure that the host vulnerabilities are mitigated. Not hardening the host system could lead to security exposures and breaches. You can use the dev-sec.io Hardening Framework for this task

  By default, host has factory settings. It is not hardened.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.3'
  tag 'cis-docker-1.13.0': '1.2'
  tag 'level:1'
  ref 'Dev-Sec Hardening Framework', url: 'http://dev-sec.io/'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  ref 'Center of Internet Security Benchmarks', url: 'https://learn.cisecurity.org/benchmarks'
  ref 'Grsecurity', url: 'https://grsecurity.net/'
  ref 'Grsecurity Wiki', url: 'https://en.wikibooks.org/wiki/Grsecurity'
  ref 'PAX Security', url: 'https://pax.grsecurity.net/'
  ref 'PAX Security Wiki', url: 'https://en.wikipedia.org/wiki/PaX'

  describe 'docker-test' do
    skip 'Harden the container host. Use the Dev-Sec Hardening Framework'
  end
end

control 'host-1.4' do
  impact 1.0
  title 'Remove all non-essential services from the host'
  desc 'Ensure that the host running the docker daemon is running only the essential services.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.4'
  tag 'level:1'
  ref 'Containers & Docker: How Secure Are They?', url: 'https://blog.docker.com/2013/08/containers-docker-how-secure-are-they/'
  ref 'Dev-Sec Hardening Framework', url: 'http://dev-sec.io/'

  describe 'docker-test' do
    skip 'Remove all non-essential services from the host. Use the Dev-Sec Hardening Framework'
  end
end

control 'host-1.5' do
  impact 1.0
  title 'Keep Docker up to date'
  desc 'There are frequent releases for Docker software that address security vulnerabilities,product bugs and bring in new functionality. Keep a tab on these product updates and upgrade as frequently as when new security vulnerabilities are fixed or deemed correct for your organization.

  Rationale: By staying up to date on Docker updates, vulnerabilities in the Docker software can be mitigated. An educated attacker may exploit known vulnerabilities when attempting to attain access or elevate privileges. Not installing regular Docker updates may leave you ith running vulnerable Docker software. It might lead to elevation privileges, unauthorized access or other security breaches. Keep a track of new releases and update as necessary.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.5'
  tag 'cis-docker-1.13.0': '1.3'
  tag 'level:1'
  ref 'Docker installation', url: 'https://docs.docker.com/engine/installation/'
  ref 'Docker releases', url: 'https://github.com/moby/moby/releases/tag/v17.03.2-ce'
  ref 'About Docker EE', url: 'https://docs.docker.com/enterprise/'

  describe docker do
    its('version.Client.Version') { should cmp >= '17.06' }
    its('version.Server.Version') { should cmp >= '17.06' }
  end
end

control 'host-1.6' do
  impact 1.0
  title 'Only allow trusted users to control Docker daemon'
  desc 'The Docker daemon currently requires \'root\' privileges. A user added to the \'docker\' group gives him full \'root\' access rights.

  Rationale: Docker allows you to share a directory between the Docker host and a guest container without limiting the access rights of the container. This means that you can start a container and map the / directory on your host to the container. The container will then be able to alter your host file system without any restrictions. In simple terms, it means that you can attain elevated privileges with just being a member of the \'docker\' group and then starting a container with mapped / directory on the host.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.6'
  tag 'cis-docker-1.13.0': '1.4'
  tag 'level:1'
  ref 'Docker Engine Security', url: 'https://docs.docker.com/engine/security/'
  ref 'On Docker security: \'docker\' group considered harmful', url: 'https://www.zopyx.com/andreas-jung/contents/on-docker-security-docker-group-considered-harmful'
  ref 'Why we don\'t let non-root users run Docker in CentOS, Fedora, or RHEL', url: 'http://www.projectatomic.io/blog/2015/08/why-we-dont-let-non-root-users-run-docker-in-centos-fedora-or-rhel/'

  describe group('docker') do
    it { should exist }
  end

  describe etc_group.where(group_name: 'docker') do
    its('users') { should include TRUSTED_USER }
  end
end

control 'host-1.7' do
  impact 1.0
  title 'Audit docker daemon'
  desc 'Audit all Docker daemon activities.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with \'root\' privileges. It is thus necessary to audit its activities and usage.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.7'
  tag 'cis-docker-1.13.0': '1.5'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /usr/bin/docker -p rwxa -k docker') }
  end
  describe service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'host-1.8' do
  impact 1.0
  title 'Audit Docker files and directories - /var/lib/docker'
  desc 'Audit /var/lib/docker.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /var/lib/docker is one such directory. It holds all the information about containers. It must be audited.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.8'
  tag 'cis-docker-1.13.0': '1.6'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /var/lib/docker -p rwxa -k docker') }
  end
end

control 'host-1.9' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/docker'
  desc 'Audit /etc/docker.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/docker is one such directory. It holds various certificates and keys used for TLS communication between Docker daemon and Docker client. It must be audited.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.9'
  tag 'cis-docker-1.13.0': '1.7'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /etc/docker -p rwxa -k docker') }
  end
end

control 'host-1.10' do
  impact 1.0
  title 'Audit Docker files and directories - docker.service'
  desc 'Audit docker.service, if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. docker.service is one such file. The docker.service file might be present if the daemon parameters have been changed by an administrator. It holds various parameters for Docker daemon. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.10'
  tag 'cis-docker-1.13.0': '1.8'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  if docker_helper.path
    rule = '-w ' + docker_helper.path + ' -p rwxa -k docker'
    describe auditd do
      its(:lines) { should include(rule) }
    end
  else
    describe 'audit docker service' do
      skip 'Cannot determine docker path'
    end
  end
end

control 'host-1.11' do
  impact 1.0
  title 'Audit Docker files and directories - docker.socket'
  desc 'Audit docker.socket, if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. docker.socket is one such file. It holds various parameters for Docker daemon socket. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.11'
  tag 'cis-docker-1.13.0': '1.9'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  if docker_helper.socket
    rule = '-w ' + docker_helper.socket + ' -p rwxa -k docker'
    describe auditd do
      its(:lines) { should include(rule) }
    end
  else
    describe 'audit docker service' do
      skip 'Cannot determine docker socket'
    end
  end
end

control 'host-1.12' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/default/docker'
  desc 'Audit /etc/default/docker , if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/default/docker is one such file. It holds various parameters for Docker daemon. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.12'
  tag 'cis-docker-1.13.0': '1.10'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /etc/default/docker -p rwxa -k docker') }
  end
end

control 'host-1.13' do
  impact 1.0
  title 'Audit Docker files and directories - /etc/docker/daemon.json'
  desc 'Audit /etc/docker/daemon.json, if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /etc/docker/daemon.json is one such file. It holds various parameters for Docker daemon. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.13'
  tag 'cis-docker-1.13.0': '1.11'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'Daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /etc/docker/daemon.json -p rwxa -k docker') }
  end
end

control 'host-1.14' do
  impact 1.0
  title 'Audit Docker files and directories - /usr/bin/docker-containerd'
  desc 'Audit /usr/bin/docker-containerd, if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /usr/bin/docker-containerd is one such file. Docker now relies on containerd and runC to spawn containers. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.14'
  tag 'cis-docker-1.13.0': '1.12'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'Containerd integration', url: 'https://github.com/docker/docker/pull/20662'
  ref 'Containerd tools', url: 'https://containerd.tools/'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /usr/bin/docker-containerd -p rwxa -k docker') }
  end
end

control 'host-1.15' do
  impact 1.0
  title 'Audit Docker files and directories - /usr/bin/docker-runc'
  desc 'Audit /usr/bin/docker-runc, if applicable.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit all Docker related files and directories. Docker daemon runs with \'root\' privileges. Its behavior depends on some key files and directories. /usr/bin/docker-runc is one such file. Docker now relies on containerd and runC to spawn containers. It must be audited, if applicable.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.15'
  tag 'cis-docker-1.13.0': '1.13'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'
  ref 'Containerd integration', url: 'https://github.com/docker/docker/pull/20662'
  ref 'Containerd tools', url: 'https://containerd.tools/'
  ref 'Opencontainers runc repository', url: 'https://github.com/opencontainers/runc'

  only_if { os.linux? }
  describe auditd do
    its(:lines) { should include('-w /usr/bin/docker-runc -p rwxa -k docker') }
  end
end
