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

  describe command('ps aux | grep docker') do
    its('stdout') { should match (/--icc=false/) }
  end
end

control 'cis-docker-2.2' do
  impact 1.0
  title 'Set the logging level'
  desc 'Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A base log level of \'info\' and above would capture all logs except debug logs. Until and unless required, you should not run Docker daemon at \'debug\' log level.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe command('ps aux | grep docker') do
    its('stdout') { should match (/(--log-level="info")|(-l info)/) }
  end
end
