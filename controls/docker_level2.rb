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

title 'CIS Docker Benchmark - Level 2 - Docker'

# attributes
AUTHORIZATION_PLUGIN = attribute(
  'authorization_plugin',
  description: 'define authorization plugin to manage access to Docker daemon. cis-docker-benchmark-2.11',
  default: 'authz-broker'
)

LOG_DRIVER = attribute(
  'log_driver',
  description: 'define preferable way to store logs. cis-docker-benchmark-2.12',
  default: 'syslog'
)

LOG_OPTS = attribute(
  'log_opts',
  description: 'define Docker daemon log-opts. cis-docker-benchmark-2.12',
  default: /syslog-address/
)

APP_ARMOR_PROFILE = attribute(
  'app_armor_profile',
  description: 'define apparmor profile for Docker containers. cis-docker-benchmark-5.1',
  default: 'docker-default'
)

SELINUX_PROFILE = attribute(
  'selinux_profile',
  description: 'define SELinux profile for Docker containers. cis-docker-benchmark-5.2',
  default:  /label\:level\:s0-s0\:c1023/
)

SWARM_MODE = attribute(
  'SWARM_MODE',
  description: 'define the swarm mode, active or inactive',
  default:  'Swarm: inactive'
)

# check if docker exists
only_if do
  command('docker').exist?
end

control 'cis-docker-benchmark-2.8' do
  impact 1.0
  title 'Enable user namespace support'
  desc 'Enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where containers you are using do not have an explicit container user defined in the container image. If container images that you are using have a pre-defined non-root user, this recommendation may be skipped since this feature is still in its infancy and might give you unpredictable issues and complexities.'

  tag 'daemon'
  tag cis: 'docker:2.8'
  tag level: 2
  ref 'User namespeces', url: 'http://man7.org/linux/man-pages/man7/user_namespaces.7.html'
  ref 'Docker daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'
  ref 'Routing out root: user namespaces in docker', url: 'http://events.linuxfoundation.org/sites/events/files/slides/User%20Namespaces%20-%20ContainerCon%202015%20-%2016-9-final_0.pdf'
  ref 'Docker images vanish when using user namespaces ', url: 'https://github.com/docker/docker/issues/21050'

  describe json('/etc/docker/daemon.json') do
    its(['userns-remap']) { should eq('default') }
  end
  describe file('/etc/subuid') do
    it { should exist }
    it { should be_file }
  end
  describe file('/etc/subgid') do
    it { should exist }
    it { should be_file }
  end
end

control 'cis-docker-benchmark-2.9' do
  impact 1.0
  title 'Confirm default cgroup usage'
  desc 'The --cgroup-parent option allows you to set the default cgroup parent to use for all the containers. If there is no specific use case, this setting should be left at its default.'

  tag 'daemon'
  tag cis: 'docker:2.9'
  tag level: 2
  ref 'Docker daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['cgroup-parent']) { should eq('docker') }
  end
end

control 'cis-docker-benchmark-2.10' do
  impact 1.0
  title 'Do not change base device size until needed'
  desc 'In certain circumstances, you might need containers bigger than 10G in size. In these cases, carefully choose the base device size.'

  tag 'daemon'
  tag cis: 'docker:2.10'
  tag level: 2
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'

  describe json('/etc/docker/daemon.json') do
    its(['storage-opts']) { should eq(['dm.basesize=10G']) }
  end
end

control 'cis-docker-benchmark-2.11' do
  impact 1.0
  title 'Use authorization plugin'
  desc 'Docker’s out-of-the-box authorization model is all or nothing. Any user with permission to access the Docker daemon can run any Docker client command. The same is true for callers using Docker’s remote API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to Docker daemon.'

  tag 'daemon'
  tag cis: 'docker:2.11'
  tag level: 2
  ref 'Access authorization', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#access-authorization'
  ref 'Auhtorization plugins', url: 'https://docs.docker.com/engine/extend/plugins_authorization/'
  ref 'Twistlock authorization plugin', url: 'https://github.com/twistlock/authz'

  describe json('/etc/docker/daemon.json') do
    its(['authorization-plugins']) { should_not be_empty }
    its(['authorization-plugins']) { should eq([AUTHORIZATION_PLUGIN]) }
  end
end

control 'cis-docker-benchmark-2.12' do
  impact 1.0
  title 'Configure centralized and remote logging'
  desc 'Docker now supports various log drivers. A preferable way to store logs is the one that supports centralized and remote logging.'

  tag 'daemon'
  tag cis: 'docker:2.12'
  tag level: 2
  ref 'Logging overview', url: 'https://docs.docker.com/engine/admin/logging/overview/'

  describe json('/etc/docker/daemon.json') do
    its(['log-driver']) { should_not be_empty }
    its(['log-driver']) { should eq(LOG_DRIVER) }
    its(['log-opts']) { should include(LOG_OPTS) }
  end
end

control 'cis-docker-benchmark-2.13' do
  impact 1.0
  title 'Disable operations on legacy registry (v1)'
  desc 'The latest Docker registry is v2. All operations on the legacy registry version (v1) should be restricted.'

  tag 'daemon'
  tag cis: 'docker:2.13'
  tag level: 2
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'
  ref 'Proposal: Provenance step 1 - Transform images for validation and verification', url: 'https://github.com/docker/docker/issues/8093'
  ref 'Proposal: JSON Registry API V2.1', url: 'https://github.com/docker/docker/issues/9015'
  ref 'Registry next generation', url: 'https://github.com/docker/docker-registry/issues/612'
  ref 'Docker Registry HTTP API V2', url: 'https://docs.docker.com/registry/spec/api/'
  ref 'Creating Private Docker Registry 2.0 with Token Authentication Service', url: 'https://the.binbashtheory.com/creating-private-docker-registry-2-0-with-token-authentication-service/'
  ref 'New Tool to Migrate From V1 Registry to Docker Trusted Registry or V2 Open Source Registry', url: 'https://blog.docker.com/2015/07/new-tool-v1-registry-docker-trusted-registry-v2-open-source/'
  ref 'Docker Registry V2', url: 'https://www.slideshare.net/Docker/docker-registry-v2'

  describe json('/etc/docker/daemon.json') do
    its(['disable-legacy-registry']) { should eq(true) }
  end
end

control 'cis-docker-benchmark-2.14' do
  impact 1.0
  title 'Enable live restore'
  desc 'The \'--live-restore\' enables full support of daemon-less containers in docker. It ensures that docker does not stop containers on shutdown or restore and properly reconnects to the container when restarted.'

  tag 'daemon'
  tag cis: 'docker:2.14'
  tag level: 2
  ref 'Add --live-restore flag', url: 'https://github.com/docker/docker/pull/23213'

  describe json('/etc/docker/daemon.json') do
    its(['live-restore']) { should eq(true) }
  end
end

control 'cis-docker-benchmark-2.15' do
  impact 1.0
  title 'Do not enable swarm mode, if not needed'
  desc 'Do not enable swarm mode on a docker engine instance unless needed.'

  tag 'daemon'
  tag cis: 'docker:2.15'
  tag level: 2
  ref 'docker swarm init', url: 'https://docs.docker.com/engine/reference/commandline/swarm_init/'

  describe command('docker info') do
    its('stdout') { should include SWARM_MODE }
  end
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

control 'cis-docker-benchmark-5.1' do
  impact 1.0
  title 'Verify AppArmor Profile, if applicable'
  desc 'AppArmor is an effective and easy-to-use Linux application security system. It is available on quite a few Linux distributions by default such as Debian and Ubuntu.'

  tag 'daemon'
  tag cis: 'docker:5.1'
  tag level: 2
  ref 'https://docs.docker.com/engine/security/security/'
  ref 'https://docs.docker.com/engine/reference/run/#security-configuration'
  ref 'http://wiki.apparmor.net/index.php/Main_Page'

  only_if { %w(ubuntu debian).include? os[:name] }
  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(['AppArmorProfile']) { should include(APP_ARMOR_PROFILE) }
      its(['AppArmorProfile']) { should_not eq nil }
    end
  end
end

control 'cis-docker-benchmark-5.2' do
  impact 1.0
  title 'Verify SELinux security options, if applicable'
  desc 'SELinux is an effective and easy-to-use Linux application security system. It is available on quite a few Linux distributions by default such as Red Hat and Fedora'

  tag 'daemon'
  tag cis: 'docker:5.2'
  tag level: 2
  ref 'Bug: Wrong SELinux label for devmapper device', url: 'https://github.com/docker/docker/issues/22826'
  ref 'Bug: selinux break docker user namespace', url: 'https://bugzilla.redhat.com/show_bug.cgi?id=1312665'
  ref url: 'https://docs.docker.com/engine/security/security/'
  ref url: 'https://docs.docker.com/engine/reference/run/#security-configuration'
  ref url: 'https://docs.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/'

  only_if { %w(centos redhat).include? os[:name] }
  describe json('/etc/docker/daemon.json') do
    its(['selinux-enabled']) { should eq(true) }
  end

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig SecurityOpt)) { should_not eq nil }
      its(%w(HostConfig SecurityOpt)) { should include(SELINUX_PROFILE) }
    end
  end
end

control 'cis-docker-benchmark-5.22' do
  impact 1.0
  title 'Do not docker exec commands with privileged option'
  desc 'Do not docker exec with --privileged option.'

  tag 'daemon'
  tag cis: 'docker:5.22'
  tag level: 2
  ref url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep privileged').stdout do
    it { should be_empty }
  end
end

control 'cis-docker-benchmark-5.23' do
  impact 1.0
  title 'Do not docker exec commands with user option'
  desc 'Do not docker exec with --user option.'

  tag 'daemon'
  tag cis: 'docker:5.23'
  tag level: 2
  ref url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep user').stdout do
    it { should be_empty }
  end
end
