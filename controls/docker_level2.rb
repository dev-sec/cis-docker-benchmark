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
attrs = {}
# define authorization plugin to manage access to Docker daemon. cis-docker-benchmark-2.11
attrs['AUTHORIZATION_PLUGIN'] = [ENV['AUTHORIZATION_PLUGIN'] || 'authz-broker']
# define preferable way to store logs. cis-docker-benchmark-2.12
attrs['LOG_DRIVER'] = ENV['LOG_DRIVER'] || 'syslog'
# define Docker daemon log-opts. cis-docker-benchmark-2.12
attrs['LOG_OPTS'] = ENV['LOG_OPTS'] || /syslog-address/
# define apparmor profile for Docker containers. cis-docker-benchmark-5.1
attrs['APP_ARMOR_PROFILE'] = ENV['APP_ARMOR_PROFILE'] || 'docker-default'
# define SELinux profile for Docker containers. cis-docker-benchmark-5.2
attrs['SELINUX_PROFILE'] = ENV['SELINUX_PROFILE'] || /label\:level\:s0-s0\:c1023/

# check if docker exists
only_if do
  command('docker').exist?
end

control 'cis-docker-benchmark-2.8' do
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

control 'cis-docker-benchmark-2.9' do
  impact 1.0
  title 'Confirm default cgroup usage'
  desc 'The --cgroup-parent option allows you to set the default cgroup parent to use for all the containers. If there is no specific use case, this setting should be left at its default.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['cgroup-parent']) { should eq('docker') }
  end
end

control 'cis-docker-benchmark-2.10' do
  impact 1.0
  title 'Do not change base device size until needed'
  desc 'In certain circumstances, you might need containers bigger than 10G in size. In these cases, carefully choose the base device size.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'

  describe json('/etc/docker/daemon.json') do
    its(['storage-opts']) { should eq(['dm.basesize=10G']) }
  end
end

control 'cis-docker-benchmark-2.11' do
  impact 1.0
  title 'Use authorization plugin'
  desc 'Docker’s out-of-the-box authorization model is all or nothing. Any user with permission to access the Docker daemon can run any Docker client command. The same is true for callers using Docker’s remote API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to Docker daemon.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/#access-authorization'
  ref 'https://docs.docker.com/engine/extend/plugins_authorization/'
  ref 'https://github.com/twistlock/authz'
  ref 'https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/'

  describe json('/etc/docker/daemon.json') do
    its(['authorization-plugins']) { should_not be_empty }
  end
  describe json('/etc/docker/daemon.json') do
    its(['authorization-plugins']) { should eq(attrs['AUTHORIZATION_PLUGIN']) }
  end
end

control 'cis-docker-benchmark-2.12' do
  impact 1.0
  title 'Configure centralized and remote logging'
  desc 'Docker now supports various log drivers. A preferable way to store logs is the one that supports centralized and remote logging.'
  tag 'Bug: logs-opts seems broken in daemon.json https://github.com/docker/docker/issues/22311'
  ref 'https://docs.docker.com/engine/admin/logging/overview/'

  describe json('/etc/docker/daemon.json') do
    its(['log-driver']) { should_not be_empty }
  end
  describe json('/etc/docker/daemon.json') do
    its(['log-driver']) { should eq(attrs['LOG_DRIVER']) }
  end
  describe json('/etc/docker/daemon.json') do
    its(['log-opts']) { should include(attrs['LOG_OPTS']) }
  end
end

control 'cis-docker-benchmark-2.13' do
  impact 1.0
  title 'Disable operations on legacy registry (v1)'
  desc 'The latest Docker registry is v2. All operations on the legacy registry version (v1) should be restricted.'
  ref 'https://docs.docker.com/engine/reference/commandline/daemon/'
  ref 'https://github.com/docker/docker/issues/8093'
  ref 'https://github.com/docker/docker/issues/9015'
  ref 'https://github.com/docker/docker-registry/issues/612'

  describe json('/etc/docker/daemon.json') do
    its(['disable-legacy-registry']) { should eq(true) }
  end
end

control 'cis-docker-benchmark-4.5' do
  impact 1.0
  title 'Enable Content trust for Docker'
  desc 'Content trust provides the ability to use digital signatures for data sent to and received from remote Docker registries. These signatures allow client-side verification of the integrity and publisher of specific image tags. This ensures provenance of container images. Content trust is disabled by default. You should enable it.'
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
  ref 'https://docs.docker.com/engine/security/security/'
  ref 'https://docs.docker.com/engine/reference/run/#security-configuration'
  ref 'http://wiki.apparmor.net/index.php/Main_Page'

  only_if { os[:family] == ('ubuntu' || 'debian') }
  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(['AppArmorProfile']) { should include(attrs['APP_ARMOR_PROFILE']) }
      its(['AppArmorProfile']) { should_not eq nil }
    end
  end
end

control 'cis-docker-benchmark-5.2' do
  impact 1.0
  title 'Verify SELinux security options, if applicable'
  desc 'SELinux is an effective and easy-to-use Linux application security system. It is available on quite a few Linux distributions by default such as Red Hat and Fedora'
  tag 'Bug: Wrong SELinux label for devmapper device https://github.com/docker/docker/issues/22826'
  tag 'Bug: selinux break docker user namespace https://bugzilla.redhat.com/show_bug.cgi?id=1312665'
  ref 'https://docs.docker.com/engine/security/security/'
  ref 'https://docs.docker.com/engine/reference/run/#security-configuration'
  ref 'https://docs.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/'

  only_if { os[:family] == ('centos' || 'redhat') }
  describe json('/etc/docker/daemon.json') do
    its(['selinux-enabled']) { should eq(true) }
  end

  docker.ps.each do |id|
    describe docker.inspect(id) do
      its(%w(HostConfig SecurityOpt)) { should_not eq nil }
      its(%w(HostConfig SecurityOpt)) { should include(attrs['SELINUX_PROFILE']) }
    end
  end
end

control 'cis-docker-benchmark-5.22' do
  impact 1.0
  title 'Do not docker exec commands with privileged option'
  desc 'Do not docker exec with --privileged option.'
  ref 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep privileged').stdout do
    it { should be_empty }
  end
end

control 'cis-docker-benchmark-5.23' do
  impact 1.0
  title 'Do not docker exec commands with user option'
  desc 'Do not docker exec with --user option.'
  ref 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep user').stdout do
    it { should be_empty }
  end
end
