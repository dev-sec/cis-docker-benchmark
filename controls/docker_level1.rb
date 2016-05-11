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
  desc 'Docker considers a private registry either secure or insecure. By default, registries are considered secure'
  ref 'https://docs.docker.com/registry/insecure/'

  describe json('/etc/docker/daemon.json') do
    its(['insecure-registries']) { should be_empty }
  end
end
