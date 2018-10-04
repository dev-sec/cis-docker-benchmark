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

title 'Container Images and Build File'

# attributes
CONTAINER_USER = attribute('container_user')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-4.1' do
  impact 1.0
  title 'Create a user for the container'
  desc 'Create a non-root user for the container in the Dockerfile for the container image.

  Rationale: It is a good practice to run the container as a non-root user, if possible. Though user namespace mapping is now available, if a user is already defined in the container image, the container is run as that user by default and specific user namespace remapping is not required.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.1'
  tag 'cis-docker-1.13.0': '4.1'
  tag 'level:1'
  ref 'Having non-root privileges on the host and root inside the container', url: 'https://github.com/docker/docker/issues/2918'
  ref 'Support for user namespaces', url: 'https://github.com/docker/docker/pull/4572'
  ref 'Proposal: Support for user namespaces', url: 'https://github.com/docker/docker/issues/7906'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[Config User]) { should_not eq nil }
      its(%w[Config User]) { should eq CONTAINER_USER }
    end
  end
end

control 'docker-4.2' do
  impact 1.0
  title 'Use trusted base images for containers'
  desc 'Ensure that the container image is written either from scratch or is based on another established and trusted base image downloaded over a secure channel.

  Rationale: Official repositories are Docker images curated and optimized by the Docker community or the vendor. There could be other potentially unsafe public repositories. You should thus exercise a lot of caution when obtaining container images.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.2'
  tag 'cis-docker-1.13.0': '4.2'
  tag 'level:1'
  ref 'Docker Image Insecurity', url: 'https://titanous.com/posts/docker-insecurity'
  ref 'Docker Hub', url: 'https://hub.docker.com/'
  ref 'Docker 1.3: signed images, process injection, security options, Mac shared directories', url: 'https://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/'
  ref 'Proposal: Provenance step 1 - Transform images for validation and verification', url: 'https://github.com/docker/docker/issues/8093'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Add support for referring to images by digest', url: 'https://github.com/docker/docker/pull/11109'
  ref 'Announcing Docker Trusted Registry 1.4 – New User Interface, Integrated Content Trust and Support for Docker Engine 1.9', url: 'https://blog.docker.com/2015/11/docker-trusted-registry-1-4/'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control 'docker-4.3' do
  impact 1.0
  title 'Do not install unnecessary packages in the container'
  desc 'Containers tend to be minimal and slim down versions of the Operating System. Do not install anything that does not justify the purpose of container.

  Rationale: Bloating containers with unnecessary software could possibly increase the attack surface of the container. This also voids the concept of minimal and slim down versions of container images. Hence, do not install anything else apart from what is truly needed for the purpose of the container.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.3'
  tag 'cis-docker-1.13.0': '4.3'
  tag 'level:1'
  ref 'Get Started, Part 1: Orientation and setup', url: 'https://docs.docker.com/get-started/'
  ref 'Slimming down your Docker containers with Alpine Linux', url: 'http://www.livewyer.com/blog/2015/02/24/slimming-down-your-docker-containers-alpine-linux'
  ref 'busybox', url: 'https://github.com/progrium/busybox'

  describe 'docker-test' do
    skip 'Do not install unnecessary packages in the container'
  end
end

control 'docker-4.4' do
  impact 1.0
  title 'Rebuild the images to include security patches'
  desc 'Instead of patching your containers and images, rebuild the images from scratch and instantiate new containers from it.

  Rationale: Vulnerabilities are loopholes/bugs that can be exploited and security patches are updates to resolve these vulnerabilities. We can use image vulnerability scanning tools to find any kind of vulnerabilities within the images and then check for available patches to mitigate these vulnerabilities. Patches update the system to the most recent code base. Being on the current code base is important because that\'s where vendors focus on fixing problems. Evaluate the security patches before applying and follow the patching best practices. Also, it would be better if, image vulnerability scanning tools could perform binary level analysis or hash based verification instead of just version string matching.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.4'
  tag 'cis-docker-1.13.0': '4.4'
  tag 'level:1'
  ref 'Get Started, Part 1: Orientation and setup', url: 'https://docs.docker.com/get-started/'
  ref 'Docker Security Scan', url: ' https://docs.docker.com/docker-cloud/builds/image-scan/'
  ref 'Docker Security Scanning safeguards the container content lifecycle', url: 'https://blog.docker.com/2016/05/docker-security-scanning/'
  ref 'Dockerfile reference', url: 'https://docs.docker.com/engine/reference/builder/'

  describe 'docker-test' do
    skip 'Rebuild the images to include security patches'
  end
end

control 'docker-4.5' do
  impact 1.0
  title 'Enable Content trust for Docker'
  desc 'Content trust is disabled by default. You should enable it.

  Rationale: Content trust provides the ability to use digital signatures for data sent to and received from remote Docker registries. These signatures allow client-side verification of the integrity and publisher of specific image tags. This ensures provenance of container images.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.5'
  tag 'cis-docker-1.13.0': '4.5'
  tag 'level:2'
  ref 'Content trust in Docker', url: 'https://docs.docker.com/engine/security/trust/content_trust/'
  ref 'Notary', url: 'https://docs.docker.com/engine/reference/commandline/cli/#notary'
  ref 'Environment variables', url: 'https://docs.docker.com/engine/reference/commandline/cli/#environment-variables'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control 'docker-4.6' do
  impact 0.0
  title 'Add HEALTHCHECK instruction to the container image'
  desc 'Add HEALTHCHECK instruction in your docker container images to perform the health check on running containers.

  Rationale: One of the important security triads is availability. Adding HEALTHCHECK instruction to your container image ensures that the docker engine periodically checks the running container instances against that instruction to ensure that the instances are still working. Based on the reported health status, the docker engine could then exit non-working containers and instantiate new ones.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.6'
  tag 'cis-docker-1.13.0': '4.6'
  tag 'level:1'
  ref 'Add support for user-defined healthchecks', url: 'https://github.com/moby/moby/pull/22719'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[Config Healthcheck]) { should_not eq nil }
    end
  end
end

control 'docker-4.7' do
  impact 1.0
  title 'Do not use update instructions alone in the Dockerfile'
  desc 'Do not use update instructions such as apt-get update alone or in a single line in the Dockerfile.

  Rationale: Adding the update instructions in a single line on the Dockerfile will cache the update layer. Thus, when you build any image later using the same instruction, previously cached update layer will be used. This could potentially deny any fresh updates to go in the later builds.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.7'
  tag 'cis-docker-1.13.0': '4.7'
  tag 'level:1'
  ref 'Best practices for writing Dockerfiles', url: 'https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/'
  ref 'caching and apt-get update', url: 'https://github.com/moby/moby/issues/3313'

  docker.images.ids.each do |id|
    describe command("docker --no-trunc history #{id}| grep -e 'update'") do
      its('stdout') { should eq '' }
    end
  end
end

control 'docker-4.8' do
  impact 1.0
  title 'Remove setuid and setgid permissions in the images'
  desc 'Removing setuid and setgid permissions in the images would prevent privilege escalation attacks in the containers.

  Rationale: setuid and setgid permissions could be used for elevating privileges. While these permissions are at times legitimately needed, these could potentially be used in privilege escalation attacks. Thus, you should consider dropping these permissions for the packages which do not need them within the images.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.8'
  tag 'cis-docker-1.13.0': '4.8'
  tag 'level:2'
  ref 'DevSec Linux Baseline', url: 'https://github.com/dev-sec/linux-baseline'
  ref 'Docker Security', url: 'http://www.oreilly.com/webops-perf/free/files/docker-security.pdf'
  ref 'Docker Security Cheat Sheet', url: 'http://container-solutions.com/content/uploads/2015/06/15.06.15_DockerCheatSheet_A2.pdf'
  ref 'setuid - set user identity', url: 'http://man7.org/linux/man-pages/man2/setuid.2.html'
  ref 'setgid - set group identity', url: 'http://man7.org/linux/man-pages/man2/setgid.2.html'

  describe 'docker-test' do
    skip 'Use DevSec Linux Baseline in Container'
  end
end

control 'docker-4.9' do
  impact 1.0
  title 'Use COPY instead of ADD in Dockerfile'
  desc 'Use COPY instruction instead of ADD instruction in the Dockerfile.

  Rationale: COPY instruction just copies the files from the local host machine to the container file system. ADD instruction potentially could retrieve files from remote URLs and perform operations such as unpacking. Thus, ADD instruction introduces risks such as adding malicious files from URLs without scanning and unpacking procedure vulnerabilities.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.9'
  tag 'cis-docker-1.13.0': '4.9'
  tag 'level:1'
  ref 'Best practices for writing Dockerfiles', url: 'https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/'

  docker.images.ids.each do |id|
    describe command("docker --no-trunc history #{id}| grep 'ADD'") do
      its('stdout') { should eq '' }
    end
  end
end

control 'docker-4.10' do
  impact 1.0
  title 'Do not store secrets in Dockerfiles'
  desc 'Do not store any secrets in Dockerfiles.

  Rationale: Dockerfiles could be backtracked easily by using native Docker commands such as docker history and various tools and utilities. Also, as a general practice, image publishers provide Dockerfiles to build the credibility for their images. Hence, the secrets within these Dockerfiles could be easily exposed and potentially be exploited.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '4.10'
  tag 'cis-docker-1.13.0': '4.10'
  tag 'level:1'
  ref 'Secrets: write-up best practices, do\'s and don\'ts, roadmap', url: 'https://github.com/moby/moby/issues/13490'
  ref 'The Twelve-Factor App', url: 'https://12factor.net/config'
  ref 'Twitter\'s Vine Source code dump', url: 'https://avicoder.me/2016/07/22/Twitter-Vine-Source-code-dump/'

  describe 'docker-test' do
    skip 'Manually verify that you have not used secrets in images'
  end
end

control 'docker-4.11' do
  impact 1.0
  title 'Install verified packages only'
  desc 'Verify authenticity of the packages before installing them in the image.

  Rationale: Verifying authenticity of the packages is essential for building a secure container image. Tampered packages could potentially be malicious or have some known vulnerabilities that could be exploited.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '4.11'
  tag 'level:1'
  ref 'Docker Security', url: 'http://www.oreilly.com/webops-perf/free/files/docker-security.pdf'
  ref 'Dockerfile HTTPD', url: 'https://github.com/docker-library/httpd/blob/12bf8c8883340c98b3988a7bade8ef2d0d6dcf8a/2.4/Dockerfile'
  ref 'Dockerfile PHP Alpine', url: 'https://github.com/docker-library/php/blob/d8a4ccf4d620ec866d5b42335b699742df08c5f0/7.0/alpine/Dockerfile'
  ref 'Product Signing (GPG) Keys', url: 'https://access.redhat.com/security/team/key'

  describe 'docker-test' do
    skip 'Manually verify that you installed verified packages'
  end
end
