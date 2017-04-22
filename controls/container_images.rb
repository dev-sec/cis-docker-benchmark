# encoding: utf-8
# frozen_string_literal: true
#
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

title 'Container Images and Build File'

# attributes
CONTAINER_USER = attribute(
  'container_user',
  description: 'define user within containers. cis-docker-benchmark-4.1',
  default: 'ubuntu'
)

# check if docker exists
only_if do
  command('docker').exist?
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

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w(Config User)) { should_not eq nil }
      its(%w(Config User)) { should eq CONTAINER_USER }
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

control 'cis-docker-benchmark-4.5' do
  impact 1.0
  title 'Enable Content trust for Docker'
  desc 'Content trust provides the ability to use digital signatures for data sent to and received from remote Docker registries. These signatures allow client-side verification of the integrity and publisher of specific image tags. This ensures provenance of container images. Content trust is disabled by default. You should enable it.'

  tag 'daemon'
  tag cis: 'docker:4.5'
  tag level: 2
  ref 'https://docs.docker.com/engine/reference/commandline/cli/#notary'
  ref 'https://docs.docker.com/engine/reference/commandline/cli/#environment-variables'
  ref 'https://docs.docker.com/engine/security/trust/content_trust/'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control 'cis-docker-benchmark-4.6' do
  impact 0.0
  title 'Add HEALTHCHECK instruction to the container image'

  tag 'daemon'
  tag cis: 'docker:4.6'
  tag level: 1

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w(Config Healthcheck)) { should_not eq nil }
    end
  end
end

control 'cis-docker-benchmark-4.7' do
  impact 0.0
  title 'Do not use update instructions alone in the Dockerfile'

  tag 'daemon'
  tag cis: 'docker:4.6'
  tag level: 1

  docker.images.ids.each do |id|
    describe command("docker history #{id}| grep -e 'update'") do
      its('stdout') { should eq '' }
    end
  end
end

control 'cis-docker-benchmark-4.8' do
  impact 0.0
  title 'Remove setuid and setgid permissions in the images'

  tag 'daemon'
  tag cis: 'docker:4.8'
  tag level: 2
  ref url: 'https://github.com/dev-sec/linux-baseline'

  describe 'docker-test' do
    skip 'Use DevSec Linux Baseline in Container'
  end
end

control 'cis-docker-benchmark-4.9' do
  impact 0.3
  title 'Use COPY instead of ADD in Dockerfile'

  tag 'daemon'
  tag cis: 'docker:4.9'
  tag level: 1

  docker.images.ids.each do |id|
    describe command("docker history #{id}| grep 'ADD'") do
      its('stdout') { should eq '' }
    end
  end
end

control 'cis-docker-benchmark-4.10' do
  impact 0.0
  title 'Do not store secrets in Dockerfiles'

  tag 'daemon'
  tag cis: 'docker:4.10'
  tag level: 1

  describe 'docker-test' do
    skip 'Manually verify that you have not used secrets in images'
  end
end
