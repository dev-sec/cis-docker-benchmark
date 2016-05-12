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

title 'CIS Docker Benchmark - Level 1 - Docker'

only_if do
  command('docker').exist?
end

control 'cis-docker-2.1' do
  impact 1.0
  title 'Restrict network traffic between containers'
  desc 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.'
  ref 'https://docs.docker.com/engine/userguide/networking/default_network/container-communication/'
  ref 'https://entwickler.de/online/development/docker-netzwerk-container-microservices-126443.html'

  describe json('/etc/docker/daemon.json') do
    its(['icc']) { should eq(false) }
  end
end

control 'cis-docker-2.2' do
  impact 1.0
  title 'Set the logging level'
  desc 'Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A ase log level of \'info\' and above would capture all logs except debug logs. Until and unless required, you should not run docker daemon at \'debug\' log level.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['log-level']) { should eq('info') }
  end
end

control 'cis-docker-2.3' do
  impact 1.0
  title 'Allow Docker to make changes to iptables'
  desc 'Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the Linux kernel. Allow the Docker daemon to make changes to the iptables.'
  ref 'https://docs.docker.com/v1.8/articles/networking/'

  describe json('/etc/docker/daemon.json') do
    its(['iptables']) { should eq(true) }
  end
end

control 'cis-docker-2.4' do
  impact 1.0
  title 'Do not use insecure registries'
  desc 'Docker considers a private registry either secure or insecure. By default, registries are considered secure.'
  ref 'https://docs.docker.com/registry/insecure/'

  describe json('/etc/docker/daemon.json') do
    its(['insecure-registries']) { should be_empty }
  end
end

control 'cis-docker-2.5' do
  impact 1.0
  title 'Do not use the aufs storage driver'
  desc 'The \'aufs\' storage driver is the oldest storage driver. It is based on a Linux kernel patch-set that is unlikely to be merged into the main Linux kernel. \'aufs\' driver is also known to cause some serious kernel crashes. \'aufs\' just has legacy support from Docker. Most importantly, \'aufs\' is not a supported driver in many Linux distributions using latest Linux kernels.'
  ref 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-storage-driver-option'
  ref 'https://github.com/docker/docker/issues/6047'
  ref 'http://muehe.org/posts/switching-docker-from-aufs-to-devicemapper/'
  ref 'http://jpetazzo.github.io/assets/2015-03-05-deep-dive-into-docker-storage-drivers.html#1'

  describe json('/etc/docker/daemon.json') do
    its(['storage-driver']) { should_not eq('aufs') }
  end
end

control 'cis-docker-2.6' do
  impact 1.0
  title 'Configure TLS authentication for Docker daemon'
  desc 'It is possible to make the Docker daemon to listen on a specific IP and port and any other Unix socket other than default Unix socket. Configure TLS authentication to restrict access to Docker daemon via IP and port.'
  ref 'https://docs.docker.com/engine/security/https/'
  ref 'http://www.hnwatcher.com/r/1644394/Intro-to-Docker-Swarm-Part-2-Comfiguration-Modes-and-Requirements'
  ref 'http://www.blackfinsecurity.com/docker-swarm-with-tls-authentication/'
  ref 'http://tech.paulcz.net/2016/01/secure-docker-with-tls/'

  describe json('/etc/docker/daemon.json') do
    its(['tls']) { should eq(true) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlsverify']) { should eq(true) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlscacert']) { should eq('/etc/docker/ssl/ca.pem') }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlscert']) { should eq('/etc/docker/ssl/server_cert.pem') }
  end
  describe json('/etc/docker/daemon.json') do
    its(['tlskey']) { should eq('/etc/docker/ssl/server_key.pem') }
  end
end

control 'cis-docker-2.7' do
  impact 1.0
  title 'Set default ulimit as appropriate'
  desc 'ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously saves you from many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/#default-ulimits'

  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits','nproc']) { should eq('1024:2408') }
  end
  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits','nofile']) { should eq('100:200') }
  end
end

control 'cis-docker-2.8' do
  impact 1.0
  title 'Enable user namespace support'
  desc 'Enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where containers you are using do not have an explicit container user defined in the container image. If container images that you are using have a pre-defined non-root user, this recommendation may be skipped since this feature is still in its infancy and might give you unpredictable issues and complexities.'
  ref 'http://man7.org/linux/man-pages/man7/user_namespaces.7.html'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/'
  ref 'http://events.linuxfoundation.org/sites/events/files/slides/User%20Namespaces%20-%20ContainerCon%202015%20-%2016-9-final_0.pdf'
  ref 'https://github.com/docker/docker/issues/21050'

  describe json('/etc/docker/daemon.json') do
    its(['userns-remap']) { should eq('default') }
  end
end
