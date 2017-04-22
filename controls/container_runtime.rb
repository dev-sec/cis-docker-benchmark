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

title 'Container Runtime'

# attributes
CONTAINER_CAPADD = attribute(
  'container_capadd',
  description: 'define needed capabilities for containers.'
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

# check if docker exists
only_if do
  command('docker').exist?
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
