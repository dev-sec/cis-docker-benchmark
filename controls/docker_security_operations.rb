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

title 'Docker Security Operations'

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-6.1' do
  impact 1.0
  title 'Perform regular security audits of your host system and containers'
  desc 'Perform regular security audits of your host system and containers to identify any mis-configurations or vulnerabilities that could expose your system to compromise.

  Rationale: Performing regular and dedicated security audits of your host systems and containers could provide deep security insights that you might not know in your daily course of business. The identified security weaknesses should be then mitigated and this overall improves security posture of your environment.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '6.1'
  tag 'cis-docker-1.13.0': '6.1'
  tag 'level:1'
  ref 'IT security auditing: Best practices for conducting audits', url: 'http://searchsecurity.techtarget.com/IT-security-auditing-Best-practices-for-conducting-audits'

  describe 'docker-test' do
    skip 'Perform regular security audits of your host system and containers'
  end
end

control 'docker-6.2' do
  impact 1.0
  title 'Monitor Docker containers usage, performance and metering'
  desc 'Containers might run services that are critical for your business. Monitoring their usage, performance and metering would be of paramount importance.

  Rationale: Tracking container usage, performance and having some sort of metering around them would be important as you embrace the containers to run critical services for your business. This would give you

      Capacity Management and Optimization
      Performance Management
      Comprehensive Visibility

  Such a deep visibility of container performance would help you ensure high availability of containers and minimum downtime.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '6.2'
  tag 'cis-docker-1.13.0': '6.2'
  tag 'level:1'
  ref 'Runtime metrics', url: 'https://docs.docker.com/engine/admin/runmetrics/'
  ref 'cAdvisor (Container Advisor)', url: 'https://github.com/google/cadvisor'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  describe 'docker-test' do
    skip 'Monitor Docker containers usage, performance and metering'
  end
end

control 'docker-6.3' do
  impact 1.0
  title 'Backup container data'
  desc 'Take regular backups of your container data volumes.

  Rationale: Containers might run services that are critical for your business. Taking regular data backups would ensure that if there is ever any loss of data you would still have your data in backup. The loss of data could be devastating for your business.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '6.3'
  tag 'cis-docker-1.13.0': '6.3'
  tag 'level:1'
  ref 'Backups and disaster recovery', url: 'https://docs.docker.com/datacenter/ucp/2.2/guides/admin/backups-and-disaster-recovery/'
  ref 'How can I backup a Docker-container with its data-volumes?', url: 'https://stackoverflow.com/questions/26331651/how-can-i-backup-a-docker-container-with-its-data-volumes'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  describe 'docker-test' do
    skip 'Backup container data'
  end
end

control 'host-6.4' do
  impact 1.0
  title 'Avoid image sprawl'
  desc 'Do not keep a large number of container images on the same host. Use only tagged images as appropriate.

  Rationale: Tagged images are useful to fall back from "latest" to a specific version of an image in production. Images with unused or old tags may contain vulnerabilities that might be exploited, if instantiated. Additionally, if you fail to remove unused images from the system and there are various such redundant and unused images, the host filesystem may become full and could lead to denial of service.'

  tag 'host'
  tag 'cis-docker-1.12.0': '6.4'
  tag 'cis-docker-1.13.0': '6.4'
  tag 'level:1'
  ref 'Clean up unused Docker Containers and Images', url: 'http://craiccomputing.blogspot.de/2014/09/clean-up-unused-docker-containers-and.html'
  ref 'Command to remove all unused images', url: 'https://forums.docker.com/t/command-to-remove-all-unused-images/20/8'
  ref 'docker rmi --unused', url: 'https://github.com/moby/moby/issues/9054'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Add support for referring to images by digest', url: 'https://github.com/moby/moby/pull/11109'

  instantiated_images = command('docker ps -qa | xargs docker inspect -f \'{{.Image}}\'').stdout.split
  all_images = command('docker images -q --no-trunc').stdout.split
  diff = all_images - instantiated_images

  describe diff do
    it { should be_empty }
  end
end

control 'host-6.5' do
  impact 1.0
  title 'Avoid container sprawl'
  desc 'Do not keep a large number of containers on the same host.

  Rationale: The flexibility of containers makes it easy to run multiple instances of applications and indirectly leads to Docker images that exist at varying security patch levels. It also means that you are consuming host resources that otherwise could have been used for running \'useful\' containers. Having more than just the manageable number of containers on a particular host makes the situation vulnerable to mishandling, misconfiguration and fragmentation. Thus, avoid container sprawl and keep the number of containers on a host to a manageable total.'

  tag 'host'
  tag 'cis-docker-1.12.0': '6.5'
  tag 'cis-docker-1.13.0': '6.5'
  tag 'level:1'
  ref 'Security Risks and Benefits of Docker Application Containers', url: 'https://zeltser.com/security-risks-and-benefits-of-docker-application/'
  ref 'Docker networking: How Linux containers will change your network', url: 'http://searchsdn.techtarget.com/feature/Docker-networking-How-Linux-containers-will-change-your-network'

  total_on_host = command('docker info').stdout.split[1].to_i
  total_running = command('docker ps -q').stdout.split.length
  diff = total_on_host - total_running

  describe diff do
    it { should be <= MANAGEABLE_CONTAINER_NUMBER }
  end
end
