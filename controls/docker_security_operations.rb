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

title 'Docker Security Operations'

# check if docker exists
only_if do
  command('docker').exist?
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

control 'cis-docker-benchmark-6.4' do
  impact 1.0
  title 'Avoid image sprawl'
  desc 'Do not keep a large number of container images on the same host. Use only tagged images as appropriate.'

  tag 'host'
  tag cis: 'docker:6.4'
  tag level: 1
  ref 'http://craiccomputing.blogspot.de/2014/09/clean-up-unused-docker-containers-and.html'
  ref 'https://forums.docker.com/t/command-to-remove-all-unused-images/20/7'
  ref 'https://github.com/docker/docker/issues/9054'
  ref 'https://docs.docker.com/engine/reference/commandline/cli/#rmi'
  ref 'https://docs.docker.com/engine/reference/commandline/cli/#pull'
  ref 'https://github.com/docker/docker/pull/11109'

  instantiated_images = command('docker ps -qa | xargs docker inspect -f \'{{.Image}}\'').stdout.split
  all_images = command('docker images -q --no-trunc').stdout.split
  diff = all_images - instantiated_images

  describe diff do
    it { should be_empty }
  end
end

control 'cis-docker-benchmark-6.5' do
  impact 1.0
  title 'Avoid container sprawl'
  desc 'Do not keep a large number of containers on the same host.'

  tag 'host'
  tag cis: 'docker:6.5'
  tag level: 1
  ref 'https://zeltser.com/security-risks-and-benefits-of-docker-application/'
  ref 'http://searchsdn.techtarget.com/feature/Docker-networking-How-Linux-containers-will-change-your-network'

  total_on_host = command('docker info').stdout.split[1].to_i
  total_running = command('docker ps -q').stdout.split.length
  diff = total_on_host - total_running

  describe diff do
    it { should be <= MANAGEABLE_CONTAINER_NUMBER }
  end
end
