# encoding: utf-8
# frozen_string_literal: true
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

title 'CIS Docker Benchmark - Level 1 - Docker'

# attributes
REGISTRY_CERT_PATH = attribute(
  'registry_cert_path',
  description: 'directory contains various Docker registry directories. cis-docker-benchmark-3.7',
  default: '/etc/docker/certs.d'
)

REGISTRY_NAME = attribute(
  'registry_name',
  description: 'directory contain certificate certain Docker registry. cis-docker-benchmark-3.7',
  default: '/etc/docker/certs.d/registry_hostname:port'
)

REGISTRY_CA_FILE = attribute(
  'registry_ca_file',
  description: 'certificate file for a certain Docker registry certificate files. cis-docker-benchmark-3.7 and cis-docker-benchmark-3.8',
  default: '/etc/docker/certs.d/registry_hostname:port/ca.crt'
)

CONTAINER_USER = attribute(
  'container_user',
  description: 'define user within containers. cis-docker-benchmark-4.1',
  default: 'ubuntu'
)

CONTAINER_CAPADD = attribute(
  'container_capadd',
  description: 'define needed capabilities for containers.'
)

DAEMON_TLSCACERT = attribute(
  'daemon_tlscacert',
  description: 'Trust certs signed only by this CA',
  default: '/etc/docker/ssl/ca.pem'
)

DAEMON_TLSCERT = attribute(
  'daemon_tlscert',
  description: 'Path to TLS certificate file',
  default: '/etc/docker/ssl/server_cert.pem'
)

DAEMON_TLSKEY = attribute(
  'daemon_tlskey',
  description: 'Path to TLS key file',
  default: '/etc/docker/ssl/server_key.pem'
)

# check if docker exists
only_if do
  command('docker').exist?
end

control 'cis-docker-benchmark-2.1' do
  impact 1.0
  title 'Restrict network traffic between containers'
  desc 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.'

  tag 'daemon'
  tag cis: 'docker:2.1'
  tag level: 1
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'

  describe json('/etc/docker/daemon.json') do
    its(['icc']) { should eq(false) }
  end
end

control 'cis-docker-benchmark-2.2' do
  impact 1.0
  title 'Set the logging level'
  desc 'Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A ase log level of \'info\' and above would capture all logs except debug logs. Until and unless required, you should not run docker daemon at \'debug\' log level.'

  tag 'daemon'
  tag cis: 'docker:2.2'
  tag level: 1
  ref 'Docker daemon', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['log-level']) { should eq('info') }
  end
end

control 'cis-docker-benchmark-2.3' do
  impact 1.0
  title 'Allow Docker to make changes to iptables'
  desc 'Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the Linux kernel. Allow the Docker daemon to make changes to the iptables.'

  tag 'daemon'
  tag cis: 'docker:2.3'
  tag level: 1
  ref 'https://docs.docker.com/v1.8/articles/networking/'

  describe json('/etc/docker/daemon.json') do
    its(['iptables']) { should eq(true) }
  end
end

control 'cis-docker-benchmark-2.4' do
  impact 1.0
  title 'Do not use insecure registries'
  desc 'Docker considers a private registry either secure or insecure. By default, registries are considered secure.'

  tag 'daemon'
  tag cis: 'docker:2.4'
  tag level: 1
  ref 'Insecure registry', url: 'https://docs.docker.com/registry/insecure/'

  describe json('/etc/docker/daemon.json') do
    its(['insecure-registries']) { should be_empty }
  end
end

control 'cis-docker-benchmark-2.5' do
  impact 1.0
  title 'Do not use the aufs storage driver'
  desc 'The \'aufs\' storage driver is the oldest storage driver. It is based on a Linux kernel patch-set that is unlikely to be merged into the main Linux kernel. \'aufs\' driver is also known to cause some serious kernel crashes. \'aufs\' just has legacy support from Docker. Most importantly, \'aufs\' is not a supported driver in many Linux distributions using latest Linux kernels.'

  tag 'daemon'
  tag cis: 'docker:2.5'
  tag level: 1
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-storage-driver-option'
  ref 'permission denied if chown after chmod', url: 'https://github.com/docker/docker/issues/6047'
  ref 'Switch from aufs to devicemapper', url: 'http://muehe.org/posts/switching-docker-from-aufs-to-devicemapper/'
  ref 'Deep dive into docker storage drivers', url: 'http://jpetazzo.github.io/assets/2015-03-05-deep-dive-into-docker-storage-drivers.html#1'

  describe json('/etc/docker/daemon.json') do
    its(['storage-driver']) { should_not eq('aufs') }
  end
end

control 'cis-docker-benchmark-2.6' do
  impact 1.0
  title 'Configure TLS authentication for Docker daemon'
  desc 'It is possible to make the Docker daemon to listen on a specific IP and port and any other Unix socket other than default Unix socket. Configure TLS authentication to restrict access to Docker daemon via IP and port.'

  tag 'daemon'
  tag cis: 'docker:2.6'
  tag level: 1
  ref 'Protect Docker deamon socket', url: 'https://docs.docker.com/engine/security/https/'

  describe json('/etc/docker/daemon.json') do
    its(['tls']) { should eq(true) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlsverify']) { should eq(true) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlscacert']) { should eq(DAEMON_TLSCACERT) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlscert']) { should eq(DAEMON_TLSCERT) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlskey']) { should eq(DAEMON_TLSKEY) }
  end
end

control 'cis-docker-benchmark-2.7' do
  impact 1.0
  title 'Set default ulimit as appropriate'
  desc 'ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously saves you from many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable.'

  tag 'daemon'
  tag cis: 'docker:2.7'
  tag level: 1
  ref 'Docker daemon deafult ulimits', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#default-ulimits'

  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits', 'nproc']) { should eq('1024:2408') }
  end
  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits', 'nofile']) { should eq('100:200') }
  end
end

control 'cis-docker-benchmark-3.1' do
  impact 1.0
  title 'Verify that docker.service file ownership is set to root:root'
  desc 'Verify that the \'docker.service\' file ownership and group-ownership are correctly set to \'root\''

  tag 'daemon'
  tag cis: 'docker:3.1'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/admin/systemd/'

  describe file(docker.path) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.2' do
  impact 1.0
  title 'Verify that docker.service file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'docker.service\' file permissions are correctly set to \'644\' or more restrictive'

  tag 'daemon'
  tag cis: 'docker:3.2'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/admin/systemd/'

  describe file(docker.path) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'cis-docker-benchmark-3.3' do
  impact 1.0
  title 'Verify that docker.socket file ownership is set to root:root'
  desc 'Verify that the \'docker.socket\' file ownership and group-ownership are correctly set to \'root\''

  tag 'daemon'
  tag cis: 'docker:3.3'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/quickstart/'
  ref url: 'https://github.com/YungSang/fedora-atomic-packer/blob/master/oem/docker.socket'
  ref url: 'https://daviddaeschler.com/2014/12/14/centos-7rhel-7-and-docker-containers-on-boot/'

  describe file(docker.socket) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.4' do
  impact 1.0
  title 'Verify that docker.socket file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'docker.socket\' file permissions are correctly set to \'644\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.4'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/quickstart/'
  ref url: 'https://github.com/YungSang/fedora-atomic-packer/blob/master/oem/docker.socket'
  ref url: 'https://daviddaeschler.com/2014/12/14/centos-7rhel-7-and-docker-containers-on-boot/'

  describe file(docker.socket) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'cis-docker-benchmark-3.5' do
  impact 1.0
  title 'Verify that /etc/docker directory ownership is set to root:root'
  desc '\'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the directory.'

  tag 'daemon'
  tag cis: 'docker:3.5'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'

  describe file('/etc/docker') do
    it { should exist }
    it { should be_directory }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.6' do
  impact 1.0
  title 'Verify that /etc/docker directory permissions are set to 755 or more restrictive'
  desc 'Verify that the /etc/docker directory permissions are correctly set to \'755\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.6'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'

  describe file('/etc/docker') do
    it { should exist }
    it { should be_directory }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_executable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should be_executable.by('other') }
  end
end

control 'cis-docker-benchmark-3.7' do
  impact 1.0
  title 'Verify that registry certificate file ownership is set to root:root'
  desc 'Verify that all the registry certificate files (usually found under /etc/docker/certs.d/<registry-name> directory) are owned and group-owned by \'root\'.'

  tag 'daemon'
  tag cis: 'docker:3.7'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'docs.docker.com/reference/commandline/cli/#insecure-registries'

  describe file(REGISTRY_CERT_PATH) do
    it { should exist }
    it { should be_directory }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe file(REGISTRY_NAME) do
    it { should exist }
    it { should be_directory }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe file(REGISTRY_CA_FILE) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.8' do
  impact 1.0
  title 'Verify that registry certificate file permissions are set to 444 or more restrictive'
  desc 'Verify that all the registry certificate files (usually found under /etc/docker/certs.d/<registry-name> directory) have permissions of \'444\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.8'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'docs.docker.com/reference/commandline/cli/#insecure-registries'

  describe file(REGISTRY_CA_FILE) do
    it { should exist }
    it { should be_file }
    it { should be_readable }
    it { should_not be_executable }
    it { should_not be_writable }
  end
end

control 'cis-docker-benchmark-3.9' do
  impact 1.0
  title 'Verify that TLS CA certificate file ownership is set to root:root'
  desc 'Verify that the TLS CA certificate file (the file that is passed alongwith \'--tlscacert\' parameter) is owned and group-owned by \'root\'.'

  tag 'daemon'
  tag cis: 'docker:3.9'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  json('/etc/docker/daemon.json').params['tlscacert']

  describe file(json('/etc/docker/daemon.json').params['tlscacert']) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.10' do
  impact 1.0
  title 'Verify that TLS CA certificate file permissions are set to 444 or more restrictive'
  desc 'Verify that the TLS CA certificate file (the file that is passed alongwith \'--tlscacert\' parameter) has permissions of \'444\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.10'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  describe file(json('/etc/docker/daemon.json').params['tlscacert']) do
    it { should exist }
    it { should be_file }
    it { should be_readable }
    it { should_not be_executable }
    it { should_not be_writable }
  end
end

control 'cis-docker-benchmark-3.11' do
  impact 1.0
  title 'Verify that Docker server certificate file ownership is set to root:root'
  desc 'Verify that the Docker server certificate file (the file that is passed alongwith \'--tlscert\' parameter) is owned and group-owned by \'root\'.'

  tag 'daemon'
  tag cis: 'docker:3.11'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  describe file(json('/etc/docker/daemon.json').params['tlscert']) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.12' do
  impact 1.0
  title 'Verify that Docker server certificate file permissions are set to 444 or more restrictive'
  desc 'Verify that the Docker server certificate file (the file that is passed alongwith \'--tlscert\' parameter) has permissions of \'444\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.12'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  describe file(json('/etc/docker/daemon.json').params['tlscert']) do
    it { should exist }
    it { should be_file }
    it { should be_readable }
    it { should_not be_executable }
    it { should_not be_writable }
  end
end

control 'cis-docker-benchmark-3.13' do
  impact 1.0
  title 'Verify that Docker server certificate key file ownership is set to root:root'
  desc 'Verify that the Docker server certificate key file (the file that is passed alongwith \'--tlskey\' parameter) is owned and group-owned by \'root\'.'

  tag 'daemon'
  tag cis: 'docker:3.13'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  describe file(json('/etc/docker/daemon.json').params['tlskey']) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.14' do
  impact 1.0
  title 'Verify that Docker server certificate key file permissions are set to 444 or more restrictive'
  desc 'Verify that the Docker server certificate key file (the file that is passed alongwith \'--tlskey\' parameter) has permissions of \'400\'.'

  tag 'daemon'
  tag cis: 'docker:3.14'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/certificates/'
  ref url: 'https://docs.docker.com/engine/security/https/'

  describe file(json('/etc/docker/daemon.json').params['tlskey']) do
    it { should exist }
    it { should be_file }
    it { should be_readable }
    it { should_not be_executable }
    it { should_not be_writable }
  end
end

control 'cis-docker-benchmark-3.15' do
  impact 1.0
  title 'Verify that Docker socket file ownership is set to root:docker'
  desc 'Verify that the Docker socket file is owned by \'root\' and group-owned by \'docker\'.'

  tag 'daemon'
  tag cis: 'docker:3.15'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-socket-option'
  ref url: 'https://docs.docker.com/engine/quickstart/'

  describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_socket }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'docker' }
  end
end

control 'cis-docker-benchmark-3.16' do
  impact 1.0
  title 'Verify that Docker socket file permissions are set to 660 or more restrictive'
  desc 'Only \'root\' and members of \'docker\' group should be allowed to read and write to default Docker Unix socket. Hence, the Docket socket file must have permissions of \'660\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.16'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-socket-option'
  ref url: 'https://docs.docker.com/engine/quickstart/'

  describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_socket }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
end

control 'cis-docker-benchmark-3.17' do
  impact 1.0
  title 'Verify that daemon.json file ownership is set to root:root'
  desc '\'daemon.json\' file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the file.'

  tag 'daemon'
  tag cis: 'docker:3.17'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/daemon/#daemon-configuration-file'

  describe file('/etc/docker/daemon.json') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.18' do
  impact 1.0
  title 'Verify that /etc/docker/daemon.json file permissions are set to 644 or more restrictive'
  desc '\'daemon.json\' file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be writable only by \'root\' to maintain the integrity of the file.'

  tag 'daemon'
  tag cis: 'docker:3.18'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-socket-option'
  ref url: 'https://docs.docker.com/engine/quickstart/'

  describe file('/etc/docker/daemon.json') do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
end

control 'cis-docker-benchmark-3.19' do
  impact 1.0
  title 'Verify that /etc/default/docker file ownership is set to root:root'
  desc '\'/etc/default/docker\' file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the file.'

  tag 'daemon'
  tag cis: 'docker:3.19'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/admin/configuring/'

  only_if { os[:family] != 'centos' }
  describe file('/etc/default/docker') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-docker-benchmark-3.20' do
  impact 1.0
  title 'Verify that /etc/default/docker file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'/etc/default/docker\' file permissions are correctly set to \'644\' or more restrictive.'

  tag 'daemon'
  tag cis: 'docker:3.20'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/admin/configuring/'

  only_if { os[:family] != 'centos' }
  describe file('/etc/default/docker') do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
end

control 'cis-docker-benchmark-4.1' do
  impact 1.0
  title 'Create a user for the container'
  desc 'Create a non-root user for the container in the Dockerfile for the container image.'

  tag 'daemon'
  tag cis: 'docker:4.1'
  tag level: 1
  ref url: 'https://github.com/docker/docker/issues/2918'
  ref url: 'https://github.com/docker/docker/pull/4572'
  ref url: 'https://github.com/docker/docker/issues/7906'
  ref url: 'https://www.altiscale.com/blog/making-docker-work-yarn/'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(Config User)) { should eq CONTAINER_USER }
      its(%w(Config User)) { should_not eq nil }
    end
  end
end

control 'cis-docker-benchmark-4.2' do
  impact 1.0
  title 'Use trusted base images for containers'
  desc 'Ensure that the container image is written either from scratch or is based on another established and trusted base image downloaded over a secure channel.'

  tag 'daemon'
  tag cis: 'docker:4.2'
  tag level: 1
  ref url: 'https://titanous.com/posts/docker-insecurity'
  ref url: 'https://hub.docker.com/'
  ref url: 'https://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/'
  ref url: 'https://github.com/docker/docker/issues/8093'
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#pull'
  ref url: 'https://github.com/docker/docker/pull/11109'
  ref url: 'https://blog.docker.com/2015/11/docker-trusted-registry-1-4/'
end

control 'cis-docker-benchmark-4.3' do
  impact 1.0
  title 'Do not install unnecessary packages in the container'
  desc 'Containers tend to be minimal and slim down versions of the Operating System. Do not install anything that does not justify the purpose of container.'

  tag 'daemon'
  tag cis: 'docker:4.3'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/containers/dockerimages/'
  ref url: 'http://www.livewyer.com/blog/2015/02/24/slimming-down-your-docker-containers-alpine-linux'
  ref url: 'https://github.com/progrium/busybox'
end

control 'cis-docker-benchmark-4.4' do
  impact 1.0
  title 'Rebuild the images to include security patches'
  desc 'Instead of patching your containers and images, rebuild the images from scratch and instantiate new containers from it.'

  tag 'daemon'
  tag cis: 'docker:4.4'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/containers/dockerimages/'
end

control 'cis-docker-benchmark-5.3' do
  impact 1.0
  title 'Restrict Linux Kernel Capabilities within containers'
  desc 'By default, Docker starts containers with a restricted set of Linux Kernel Capabilities. It means that any process may be granted the required capabilities instead of root access. Using Linux Kernel Capabilities, the processes do not have to run as root for almost all the specific areas where root privileges are usually needed.'

  tag 'daemon'
  tag cis: 'docker:5.3'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/security/security/'
  ref url: 'http://man7.org/linux/man-pages/man7/capabilities.7.html'
  ref url: 'https://github.com/docker/docker/blob/master/oci/defaults_linux.go#L64-L79'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig CapDrop)) { should include(/all/) }
      its(%w(HostConfig CapDrop)) { should_not eq nil }
      its(%w(HostConfig CapAdd)) { should eq CONTAINER_CAPADD }
    end
  end
end

control 'cis-docker-benchmark-5.4' do
  impact 1.0
  title 'Do not use privileged containers'
  desc 'Using the --privileged flag gives all Linux Kernel Capabilities to the container thus overwriting the --cap-add and --cap-drop flags. Ensure that it is not used.'

  tag 'daemon'
  tag cis: 'docker:5.4'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig Privileged)) { should eq false }
      its(%w(HostConfig Privileged)) { should_not eq true }
    end
  end
end

control 'cis-docker-benchmark-5.5' do
  impact 1.0
  title 'Do not mount sensitive host system directories on containers'
  desc 'Sensitive host system directories such as \'/, /boot, /dev, /etc, /lib, /proc, /sys, /usr\' should not be allowed to be mounted as container volumes especially in read-write mode.'

  tag 'daemon'
  tag cis: 'docker:5.5'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/containers/dockervolumes/'

  docker.ps.each do |id|
    info = docker.inspect(id)
    info['Mounts'].each do |mounts|
      describe mounts['Source'] do
        it { should_not eq '/' }
        it { should_not match(%r{\/boot}) }
        it { should_not match(%r{\/dev}) }
        it { should_not match(%r{\/etc}) }
        it { should_not match(%r{\/lib}) }
        it { should_not match(%r{\/proc}) }
        it { should_not match(%r{\/sys}) }
        it { should_not match(%r{\/usr}) }
      end
    end
  end
end

control 'cis-docker-benchmark-5.6' do
  impact 1.0
  title 'Do not run ssh within containers'
  desc 'SSH server should not be running within the container. You should SSH into the Docker host, and use nsenter tool to enter a container from a remote host.'

  tag 'daemon'
  tag cis: 'docker:5.6'
  tag level: 1
  ref url: 'https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/'

  docker.ps.each do |id|
    execute_command = 'docker exec ' + id + ' ps -e'
    describe command(execute_command) do
      its('stdout') { should_not match(/ssh/) }
    end
  end
end

control 'cis-docker-benchmark-5.7' do
  impact 1.0
  title 'Do not map privileged ports within containers'
  desc 'The TCP/IP port numbers below 1024 are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker allows a container port to be mapped to a privileged port.'

  tag 'daemon'
  tag cis: 'docker:5.7'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'
  ref url: 'https://www.adayinthelifeof.nl/2012/03/12/why-putting-ssh-on-another-port-than-22-is-bad-idea/'

  docker.ps.each do |id|
    info = docker.inspect(id)
    ports = info['NetworkSettings']['Ports'].keys
    ports.each do |item|
      info['NetworkSettings']['Ports'][item].each do |hostport|
        describe hostport['HostPort'].to_i.between?(1, 1024) do
          it { should eq false }
        end
      end
    end
  end
end

control 'cis-docker-benchmark-5.8' do
  impact 1.0
  title 'Open only needed ports on container'
  desc 'Dockerfile for a container image defines the ports to be opened by default on a container instance. The list of ports may or may not be relevant to the application you are running within the container.'

  tag 'daemon'
  tag cis: 'docker:5.8'
  tag level: 1
  ref 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'
end

control 'cis-docker-benchmark-5.9' do
  impact 1.0
  title 'Do not share the host\'s network namespace'
  desc 'The networking mode on a container when set to \'--net=host\', skips placing the container inside separate network stack. In essence, this choice tells Docker to not containerize the container\'s networking. This would network-wise mean that the container lives "outside" in the main Docker host and has full access to its network interfaces.'

  tag 'daemon'
  tag cis: 'docker:5.9'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/networking/dockernetworks/'
  ref url: 'https://github.com/docker/docker/issues/6401'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig NetworkMode)) { should_not eq 'host' }
    end
  end
end

control 'cis-docker-benchmark-5.10' do
  impact 1.0
  title 'Limit memory usage for container'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as memory limit, you can control the amount of memory that a container may consume.'

  tag 'daemon'
  tag cis: 'docker:5.10'
  tag level: 1
  ref url: 'https://goldmann.pl/blog/2014/09/11/resource-management-in-docker/'
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#run'
  ref url: 'https://docs.docker.com/v1.8/articles/runmetrics/'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig Memory)) { should_not eq 0 }
    end
  end
end

control 'cis-docker-benchmark-5.11' do
  impact 1.0
  title 'Set container CPU priority appropriately'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as CPU shares, you can control the host CPU resources that a container may consume.'

  tag 'daemon'
  tag cis: 'docker:5.11'
  tag level: 1
  ref url: 'https://goldmann.pl/blog/2014/09/11/resource-management-in-docker/'
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#run'
  ref url: 'https://docs.docker.com/v1.8/articles/runmetrics/'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig CpuShares)) { should_not eq 0 }
      its(%w(HostConfig CpuShares)) { should_not eq 1024 }
    end
  end
end

control 'cis-docker-benchmark-5.12' do
  impact 1.0
  title 'Mount container\'s root filesystem as read only'
  desc 'The container\'s root file system should be treated as a \'golden image\' and any writes to the root filesystem should be avoided. You should explicitly define a container volume for writing.'

  tag 'daemon'
  tag cis: 'docker:5.12'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#run'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig ReadonlyRootfs)) { should eq true }
    end
  end
end

control 'cis-docker-benchmark-5.13' do
  impact 1.0
  title 'Bind incoming container traffic to a specific host interface'
  desc 'By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers. Each outgoing connection will appear to originate from one of the host machine\'s own IP addresses. Only allow container services to be contacted through a specific external interface on the host machine.'

  tag 'daemon'
  tag cis: 'docker:5.13'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'

  docker.ps.each do |id|
    info = docker.inspect(id)
    ports = info['NetworkSettings']['Ports'].keys
    ports.each do |item|
      info['NetworkSettings']['Ports'][item].each do |hostip|
        describe hostip['HostIp'] do
          it { should_not eq '0.0.0.0' }
        end
      end
    end
  end
end

control 'cis-docker-benchmark-5.14' do
  impact 1.0
  title 'Set the \'on-failure\' container restart policy to 5'
  desc 'Using the \'--restart\' flag in \'docker run\' command you can specify a restart policy for how a container should or should not be restarted on exit. You should choose the \'on-failure\' restart policy and limit the restart attempts to 5.'

  tag 'daemon'
  tag cis: 'docker:5.14'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#restart-policies'

  docker.ps.each do |id|
    info = docker.inspect(id)
    only_if { info['HostConfig']['RestartPolicy']['Name'] != 'no' }
    describe info do
      its(%w(HostConfig RestartPolicy Name)) { should eq 'on-failure' }
    end
    describe info do
      its(%w(HostConfig RestartPolicy MaximumRetryCount)) { should eq 5 }
    end
  end
end

control 'cis-docker-benchmark-5.15' do
  impact 1.0
  title 'Do not share the host\'s process namespace'
  desc 'Process ID (PID) namespaces isolate the process ID number space, meaning that processes in different PID namespaces can have the same PID. This is process level isolation between containers and the host.'

  tag 'daemon'
  tag cis: 'docker:5.15'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/run/#pid-settings'
  ref url: 'http://man7.org/linux/man-pages/man7/pid_namespaces.7.html'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig PidMode)) { should_not eq 'host' }
    end
  end
end

control 'cis-docker-benchmark-5.16' do
  impact 1.0
  title 'Do not share the host\'s IPC namespace'
  desc 'IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores and message queues. IPC namespace on the host thus should not be shared with the containers and should remain isolated.'

  tag 'daemon'
  tag cis: 'docker:5.16'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/run/#ipc-settings'
  ref url: 'http://man7.org/linux/man-pages/man7/pid_namespaces.7.html'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig IpcMode)) { should_not eq 'host' }
    end
  end
end

control 'cis-docker-benchmark-5.17' do
  impact 1.0
  title 'Do not directly expose host devices to containers'
  desc 'Host devices can be directly exposed to containers at runtime. Do not directly expose host devices to containers especially for containers that are not trusted.'

  tag 'daemon'
  tag cis: 'docker:5.17'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#run'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig Devices)) { should be_empty }
    end
  end
end

control 'cis-docker-benchmark-5.18' do
  impact 1.0
  title 'Override default ulimit at runtime only if needed'
  desc 'The default ulimit is set at the Docker daemon level. However, you may override the default ulimit setting, if needed, during container runtime.'

  tag 'daemon'
  tag cis: 'docker:5.18'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#setting-ulimits-in-a-container'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig Ulimits)) { should eq nil }
    end
  end
end

control 'cis-docker-benchmark-5.19' do
  impact 1.0
  title 'Do not set mount propagation mode to shared'
  desc 'Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode until needed.'

  tag 'daemon'
  tag cis: 'docker:5.19'
  tag level: 1
  ref url: 'https://github.com/docker/docker/pull/17034'
  ref url: 'https://docs.docker.com/engine/reference/run/'
  ref url: 'https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt'

  docker.ps.each do |id|
    raw = command("docker inspect --format '{{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' #{id}").stdout
    describe raw.delete("\n").delete('\"').delete(' ') do
      it { should_not eq 'shared' }
    end
  end
end

control 'cis-docker-benchmark-5.20' do
  impact 1.0
  title 'Do not share the host\'s UTS namespace'
  desc 'UTS namespaces provide isolation of two system identifiers: the hostname and the NIS domain name. It is used for setting the hostname and the domain that is visible to running processes in that namespace. Processes running within containers do not typically require to know hostname and domain name. Hence, the namespace should not be shared with the host.'

  tag 'daemon'
  tag cis: 'docker:5.20'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/run/'
  ref url: 'http://man7.org/linux/man-pages/man7/pid_namespaces.7.html'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig UTSMode)) { should_not eq 'host' }
    end
  end
end

control 'cis-docker-benchmark-5.21' do
  impact 1.0
  title 'Do not disable default seccomp profile'
  desc 'Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile disables 44 system calls, out of 313. It should not be disabled unless it hinders your container application usage.'

  tag 'daemon'
  tag cis: 'docker:5.21'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/run/'
  ref url: 'http://blog.aquasec.com/new-docker-security-features-and-what-they-mean-seccomp-profiles'
  ref url: 'https://github.com/docker/docker/blob/master/profiles/seccomp/default.json'
  ref url: 'https://docs.docker.com/engine/security/seccomp/'
  ref url: 'https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt'
  ref url: 'https://github.com/docker/docker/pull/17034'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig SecurityOpt)) { should include(/seccomp/) }
      its(%w(HostConfig SecurityOpt)) { should_not include(/seccomp[=|:]unconfined/) }
    end
  end
end

control 'cis-docker-benchmark-5.24' do
  impact 1.0
  title 'Confirm cgroup usage'
  desc 'It is possible to attach to a particular cgroup on container run. Confirming cgroup usage would ensure that containers are running under defined cgroups.'

  tag 'daemon'
  tag cis: 'docker:5.24'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/reference/run/#specifying-custom-cgroups'
  ref url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/ch01.html'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig CgroupParent)) { should be_empty }
    end
  end
end

control 'cis-docker-benchmark-5.25' do
  impact 1.0
  title 'Restrict container from acquiring additional privileges'
  desc 'Restrict the container from acquiring additional privileges via suid or sgid bits.'

  tag 'daemon'
  tag cis: 'docker:5.25'
  tag level: 1
  ref url: 'https://github.com/projectatomic/atomic-site/issues/269'
  ref url: 'https://github.com/docker/docker/pull/20727'
  ref url: 'https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt'
  ref url: 'https://lwn.net/Articles/475678/'
  ref url: 'https://lwn.net/Articles/475362/'

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig SecurityOpt)) { should include(/no-new-privileges/) }
    end
  end
end

control 'cis-docker-benchmark-6.1' do
  impact 1.0
  title 'Perform regular security audits of your host system and containers'
  desc 'Perform regular security audits of your host system and containers to identify any mis-configurations or vulnerabilities that could expose your system to compromise.'

  tag cis: 'docker:6.1'
  tag level: 1
  ref url: 'http://searchsecurity.techtarget.com/IT-security-auditing-Best-practices-for-conducting-audits'
end

control 'cis-docker-benchmark-6.2' do
  impact 1.0
  title 'Monitor Docker containers usage, performance and metering'
  desc 'Containers might run services that are critical for your business. Monitoring their usage, performance and metering would be of paramount importance.'

  tag 'daemon'
  tag cis: 'docker:6.2'
  tag level: 1
  ref url: 'https://docs.docker.com/v1.8/articles/runmetrics/'
  ref url: 'https://github.com/google/cadvisor'
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#stats'
end

control 'cis-docker-benchmark-6.3' do
  impact 1.0
  title 'Backup container data'
  desc 'Take regular backups of your container data volumes.'

  tag 'daemon'
  tag cis: 'docker:6.3'
  tag level: 1
  ref url: 'https://docs.docker.com/engine/userguide/containers/dockervolumes/'
  ref url: 'http://stackoverflow.com/questions/26331651/how-can-i-backup-a-docker-container-with-its-data-volumes'
  ref url: 'https://docs.docker.com/engine/reference/commandline/cli/#diff'
end
