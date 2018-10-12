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

title 'Container Runtime'

# attributes
CONTAINER_CAPADD = attribute('container_capadd')
APP_ARMOR_PROFILE = attribute('app_armor_profile')
SELINUX_PROFILE = attribute('selinux_profile')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-5.1' do
  impact 1.0
  title 'Verify AppArmor Profile, if applicable'
  desc 'AppArmor is an effective and easy-to-use Linux application security system. It is available on quite a few Linux distributions by default such as Debian and Ubuntu.

  Rationale: AppArmor protects the Linux OS and applications from various threats by enforcing security policy which is also known as AppArmor profile. You can create your own AppArmor profile for containers or use the Docker\'s default AppArmor profile. This would enforce security policies on the containers as defined in the profile.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.1'
  tag 'cis-docker-1.13.0': '5.1'
  tag 'level:1'
  ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  ref 'AppArmor security profiles for Docker', url: 'https://docs.docker.com/engine/security/apparmor/'

  only_if { %w[ubuntu debian].include? os[:name] }
  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(['AppArmorProfile']) { should include(APP_ARMOR_PROFILE) }
      its(['AppArmorProfile']) { should_not eq nil }
    end
  end
end

control 'docker-5.2' do
  impact 1.0
  title 'Verify SELinux security options, if applicable'
  desc 'SELinux is an effective and easy-to-use Linux application security system. It is available on quite a few Linux distributions by default such as Red Hat and Fedora.

  Rationale: SELinux provides a Mandatory Access Control (MAC) system that greatly augments the default Discretionary Access Control (DAC) model. You can thus add an extra layer of safety by enabling SELinux on your Linux host, if applicable.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.2'
  tag 'cis-docker-1.13.0': '5.2'
  tag 'level:2'
  ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  ref 'AppArmor security profiles for Docker', url: 'https://docs.docker.com/engine/security/apparmor/'
  ref 'Bug: Wrong SELinux label for devmapper device', url: 'https://github.com/docker/docker/issues/22826'
  ref 'Bug: selinux break docker user namespace', url: 'https://bugzilla.redhat.com/show_bug.cgi?id=1312665'
  ref 'Security-Enhanced Linux', url: 'https://docs-old.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/'

  only_if { %w[centos redhat].include? os[:name] }
  describe json('/etc/docker/daemon.json') do
    its(['selinux-enabled']) { should eq(true) }
  end

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig SecurityOpt]) { should_not eq nil }
      its(%w[HostConfig SecurityOpt]) { should include(SELINUX_PROFILE) }
    end
  end
end

control 'docker-5.3' do
  impact 1.0
  title 'Restrict Linux Kernel Capabilities within containers'
  desc 'By default, Docker starts containers with a restricted set of Linux Kernel Capabilities. It means that any process may be granted the required capabilities instead of root access. Using Linux Kernel Capabilities, the processes do not have to run as root for almost all the specific areas where root privileges are usually needed.

  Rationale: Docker supports the addition and removal of capabilities, allowing use of a non-default profile. This may make Docker more secure through capability removal, or less secure through the addition of capabilities. It is thus recommended to remove all capabilities except those explicitly required for your container process.

  For example, capabilities such as below are usually not needed for container process: NET_ADMIN, SYS_ADMIN, SYS_MODULE'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.3'
  tag 'cis-docker-1.13.0': '5.3'
  tag 'level:1'
  ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  ref 'capabilities - overview of Linux capabilities', url: 'http://man7.org/linux/man-pages/man7/capabilities.7.html'
  ref 'Docker Security Book', url: 'http://www.oreilly.com/webops-perf/free/files/docker-security.pdf'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig CapDrop]) { should include(/all/) }
      its(%w[HostConfig CapDrop]) { should_not eq nil }
      its(%w[HostConfig CapAdd]) { should eq CONTAINER_CAPADD }
    end
  end
end

control 'docker-5.4' do
  impact 1.0
  title 'Do not use privileged containers'
  desc 'Using the --privileged flag gives all Linux Kernel Capabilities to the container thus overwriting the --cap-add and --cap-drop flags. Ensure that it is not used.

  Rationale: The --privileged flag gives all capabilities to the container, and it also lifts all the limitations enforced by the device cgroup controller. In other words, the container can then do almost everything that the host can do. This flag exists to allow special use-cases, like running Docker within Docker.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.4'
  tag 'cis-docker-1.13.0': '5.4'
  tag 'level:1'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig Privileged]) { should eq false }
      its(%w[HostConfig Privileged]) { should_not eq true }
    end
  end
end

control 'docker-5.5' do
  impact 1.0
  title 'Do not mount sensitive host system directories on containers'
  desc 'Sensitive host system directories such as \'/, /boot, /dev, /etc, /lib, /proc, /sys, /usr\' should not be allowed to be mounted as container volumes especially in read-write mode.

  Rationale: If sensitive directories are mounted in read-write mode, it would be possible to make changes to files within those sensitive directories. The changes might bring down security implications or unwarranted changes that could put the Docker host in compromised state.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.5'
  tag 'cis-docker-1.13.0': '5.5'
  tag 'level:1'
  ref 'Use volumes', url: 'https://docs.docker.com/engine/admin/volumes/volumes/'

  docker.containers.running?.ids.each do |id|
    info = docker.object(id)
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

control 'docker-5.6' do
  impact 1.0
  title 'Do not run ssh within containers'
  desc 'SSH server should not be running within the container. You should SSH into the Docker host, and use nsenter tool to enter a container from a remote host.

  Rationale: Running SSH within the container increases the complexity of security management by making it

            Difficult to manage access policies and security compliance for SSH server
            Difficult to manage keys and passwords across various containers
            Difficult to manage security upgrades for SSH server

  It is possible to have shell access to a container without using SSH, the needlessly increasing the complexity of security management should be avoided.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.6'
  tag 'cis-docker-1.13.0': '5.6'
  tag 'level:1'
  ref 'Why you don\'t need to run SSHd in your Docker containers', url: 'https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/'

  docker.containers.running?.ids.each do |id|
    execute_command = 'docker exec ' + id + ' ps -e'
    describe command(execute_command) do
      its('stdout') { should_not match(/ssh/) }
    end
  end
end

control 'docker-5.7' do
  impact 1.0
  title 'Do not map privileged ports within containers'
  desc 'The TCP/IP port numbers below 1024 are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker allows a container port to be mapped to a privileged port.

  Rationale: By default, if the user does not specifically declare the container port to host port mapping, Docker automatically and correctly maps the container port to one available in 49153-65535 block on the host. But, Docker allows a container port to be mapped to a privileged port on the host if the user explicitly declared it. This is so because containers are executed with NET_BIND_SERVICE Linux kernel capability that does not restrict the privileged port mapping. The privileged ports receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.7'
  tag 'cis-docker-1.13.0': '5.7'
  tag 'level:1'
  ref 'Bind container ports to the host', url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'
  ref 'Why putting SSH on another port than 22 is bad idea', url: 'https://www.adayinthelifeof.nl/2012/03/12/why-putting-ssh-on-another-port-than-22-is-bad-idea/'

  docker.containers.running?.ids.each do |id|
    container_info = docker.object(id)
    next if container_info['NetworkSettings']['Ports'].nil?
    container_info['NetworkSettings']['Ports'].each do |_, hosts|
      next if hosts.nil?
      hosts.each do |host|
        describe host['HostPort'].to_i.between?(1, 1024) do
          it { should eq false }
        end
      end
    end
  end
end

control 'docker-5.8' do
  impact 1.0
  title 'Open only needed ports on container'
  desc 'Dockerfile for a container image defines the ports to be opened by default on a container instance. The list of ports may or may not be relevant to the application you are running within the container.

  Rationale: A container can be run just with the ports defined in the Dockerfile for its image or can be arbitrarily passed run time parameters to open a list of ports. Additionally, Overtime, Dockerfile may undergo various changes and the list of exposed ports may or may not be relevant to the application you are running within the container. Opening unneeded ports increase the attack surface of the container and the containerized application. As a recommended practice, do not open unneeded ports.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.8'
  tag 'cis-docker-1.13.0': '5.8'
  tag 'level:1'
  ref 'Bind container ports to the host', url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'
end

control 'docker-5.9' do
  impact 1.0
  title 'Do not share the host\'s network namespace'
  desc 'The networking mode on a container when set to \'--net=host\', skips placing the container inside separate network stack. In essence, this choice tells Docker to not containerize the container\'s networking. This would network-wise mean that the container lives "outside" in the main Docker host and has full access to its network interfaces.

  Rationale: This is potentially dangerous. It allows the container process to open low-numbered ports like any other root process. It also allows the container to access network services like D-bus on the Docker host. Thus, a container process can potentially do unexpected things such as shutting down the Docker host. You should not use this option.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.9'
  tag 'cis-docker-1.13.0': '5.9'
  tag 'level:1'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'
  ref 'Rebooting within docker container actually reboots the host', url: 'https://github.com/docker/docker/issues/6401'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig NetworkMode]) { should_not eq 'host' }
    end
  end
end

control 'docker-5.10' do
  impact 1.0
  title 'Limit memory usage for container'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as memory limit, you can control the amount of memory that a container may consume.

  Rationale: By default, container can use all of the memory on the host. You can use memory limit mechanism to prevent a denial of service arising from one container consuming all of the host’s resources such that other containers on the same host cannot perform their intended functions. Having no limit on memory can lead to issues where one container can easily make the whole system unstable and as a result unusable.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.10'
  tag 'cis-docker-1.13.0': '5.10'
  tag 'level:1'
  ref 'Resource management in Docker', url: 'https://goldmann.pl/blog/2014/09/11/resource-management-in-docker/'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Runtime metrics', url: 'https://docs.docker.com/engine/admin/runmetrics/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig Memory]) { should_not eq 0 }
    end
  end
end

control 'docker-5.11' do
  impact 1.0
  title 'Set container CPU priority appropriately'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as CPU shares, you can control the host CPU resources that a container may consume.

  Rationale: By default, CPU time is divided between containers equally. If it is desired, to control the CPU time amongst the container instances, you can use CPU sharing feature. CPU sharing allows to prioritize one container over the other and forbids the lower priority container to claim CPU resources more often. This ensures that the high priority containers are served better.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.11'
  tag 'cis-docker-1.13.0': '5.11'
  tag 'level:1'
  ref 'Resource management in Docker', url: 'https://goldmann.pl/blog/2014/09/11/resource-management-in-docker/'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Runtime metrics', url: 'https://docs.docker.com/engine/admin/runmetrics/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig CpuShares]) { should_not eq 0 }
      its(%w[HostConfig CpuShares]) { should_not eq 1024 }
    end
  end
end

control 'docker-5.12' do
  impact 1.0
  title 'Mount container\'s root filesystem as read only'
  desc 'The container\'s root file system should be treated as a \'golden image\' and any writes to the root filesystem should be avoided. You should explicitly define a container volume for writing.

  Rationale: You should not be writing data within containers. The data volume belonging to a container should be explicitly defined and administered. This is useful in many cases where the admin controls where they would want developers to write files and errors. Also, this has other advantages such as below:

      This leads to an immutable infrastructure
      Since the container instance cannot be written to, there is no need to audit instance divergence
      Reduced security attack vectors since the instance cannot be tampered with or written to
      Ability to use a purely volume based backup without backing up anything from theinstance'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.12'
  tag 'cis-docker-1.13.0': '5.12'
  tag 'level:1'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig ReadonlyRootfs]) { should eq true }
    end
  end
end

control 'docker-5.13' do
  impact 1.0
  title 'Bind incoming container traffic to a specific host interface'
  desc 'By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers. Each outgoing connection will appear to originate from one of the host machine\'s own IP addresses. Only allow container services to be contacted through a specific external interface on the host machine.

  Rationale: If you have multiple network interfaces on your host machine, the container can accept connections on the exposed ports on any network interface. This might not be desired and may not be secured. Many a times a particular interface is exposed externally and services such as intrusion detection, intrusion prevention, firewall, load balancing, etc. are run on those interfaces to screen incoming public traffic. Hence, you should not accept incoming connections on any interface. You should only allow incoming connections from a particular external interface.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.13'
  tag 'cis-docker-1.13.0': '5.13'
  tag 'level:1'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'

  docker.containers.running?.ids.each do |id|
    container_info = docker.object(id)
    next if container_info['NetworkSettings']['Ports'].nil?
    container_info['NetworkSettings']['Ports'].each do |_, hosts|
      next if hosts.nil?
      hosts.each do |host|
        describe host['HostIp'].to_i.between?(1, 1024) do
          it { should_not eq '0.0.0.0' }
        end
      end
    end
  end
end

control 'docker-5.14' do
  impact 1.0
  title 'Set the \'on-failure\' container restart policy to 5'
  desc 'Using the \'--restart\' flag in \'docker run\' command you can specify a restart policy for how a container should or should not be restarted on exit. You should choose the \'on-failure\' restart policy and limit the restart attempts to 5.

  Rationale: If you indefinitely keep trying to start the container, it could possibly lead to a denial of service on the host. It could be an easy way to do a distributed denial of service attack especially if you have many containers on the same host. Additionally, ignoring the exit status of the container and \'always\' attempting to restart the container leads to non-investigation of the root cause behind containers getting terminated. If a container gets terminated, you should investigate on the reason behind it instead of just attempting to restart it indefinitely. Thus, it is recommended to use \'on-failure\' restart policy and limit it to maximum of 5 restart attempts.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.14'
  tag 'cis-docker-1.13.0': '5.14'
  tag 'level:1'
  ref 'Start containers automatically', url: 'https://docs.docker.com/engine/admin/start-containers-automatically/'

  docker.containers.running?.ids.each do |id|
    describe.one do
      describe docker.object(id) do
        its(%w[HostConfig RestartPolicy Name]) { should eq 'no' }
      end
      describe docker.object(id) do
        its(%w[HostConfig RestartPolicy Name]) { should eq 'on-failure' }
        its(%w[HostConfig RestartPolicy MaximumRetryCount]) { should eq 5 }
      end
    end
  end
end

control 'docker-5.15' do
  impact 1.0
  title 'Do not share the host\'s process namespace'
  desc 'Process ID (PID) namespaces isolate the process ID number space, meaning that processes in different PID namespaces can have the same PID. This is process level isolation between containers and the host.

  Rationale: PID namespace provides separation of processes. The PID Namespace removes the view of the system processes, and allows process ids to be reused including PID 1. If the host\'s PID namespace is shared with the container, it would basically allow processes within the container to see all of the processes on the host system. This breaks the benefit of process level isolation between the host and the containers. Someone having access to the container can eventually know all the processes running on the host system and can even kill the host system processes from within the container. This can be catastrophic. Hence, do not share the host\'s process namespace with the containers.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.15'
  tag 'cis-docker-1.13.0': '5.15'
  tag 'level:1'
  ref 'PID settings (–pid)', url: 'https://docs.docker.com/engine/reference/run/#pid-equivalent'
  ref 'pid_namespaces - overview of Linux PID namespaces', url: 'http://man7.org/linux/man-pages/man7/pid_namespaces.7.html'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig PidMode]) { should_not eq 'host' }
    end
  end
end

control 'docker-5.16' do
  impact 1.0
  title 'Do not share the host\'s IPC namespace'
  desc 'IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores and message queues. IPC namespace on the host thus should not be shared with the containers and should remain isolated.

  Rationale: IPC namespace provides separation of IPC between the host and containers. If the host\'s IPC namespace is shared with the container, it would basically allow processes within the container to see all of the IPC on the host system. This breaks the benefit of IPC level isolation between the host and the containers. Someone having access to the container can eventually manipulate the host IPC. This can be catastrophic. Hence, do not share the host\'s IPC namespace with the containers.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.16'
  tag 'cis-docker-1.13.0': '5.16'
  tag 'level:1'
  ref 'IPC settings (–ipc)', url: 'https://docs.docker.com/engine/reference/run/#ipc-settings---ipc'
  ref 'namespaces - overview of Linux namespaces', url: 'http://man7.org/linux/man-pages/man7/namespaces.7.html'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig IpcMode]) { should_not eq 'host' }
    end
  end
end

control 'docker-5.17' do
  impact 1.0
  title 'Do not directly expose host devices to containers'
  desc 'Host devices can be directly exposed to containers at runtime. Do not directly expose host devices to containers especially for containers that are not trusted.

  Rationale: The \'--device\' option exposes the host devices to the containers and consequently the containers can directly access such host devices. You would not require the container to run in \'privileged\' mode to access and manipulate the host devices. By default, the container will be able to read, write and mknod these devices. Additionally, it is possible for containers to remove block devices from the host. Hence, do not expose host devices to containers directly. If at all, you would want to expose the host device to a container, use the sharing permissions appropriately:

      r - read only
      w - writable
      m - mknod allowed'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.17'
  tag 'cis-docker-1.13.0': '5.17'
  tag 'level:1'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig Devices]) { should be_empty }
    end
  end
end

control 'docker-5.18' do
  impact 1.0
  title 'Override default ulimit at runtime only if needed'
  desc 'The default ulimit is set at the Docker daemon level. However, you may override the default ulimit setting, if needed, during container runtime.

  Rationale: ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously saves you from many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable. The default ulimit set at the Docker daemon level should be honored. If the default ulimit settings are not appropriate for a particular container instance, you may override them as an exception. But, do not make this a practice. If most of the container instances are overriding default ulimit settings, consider changing the default ulimit settings to something that is appropriate for your needs.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.18'
  tag 'cis-docker-1.13.0': '5.18'
  tag 'level:1'
  ref 'docker run', url: 'https://docs.docker.com/engine/reference/commandline/run/'
  ref 'Command: man setrlimit'
  ref 'Docker Security Book', url: 'http://www.oreilly.com/webops-perf/free/files/docker-security.pdf'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig Ulimits]) { should eq nil }
    end
  end
end

control 'docker-5.19' do
  impact 1.0
  title 'Do not set mount propagation mode to shared'
  desc 'Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode until needed.

  Rationale: A shared mount is replicated at all mounts and the changes made at any mount point are propagated to all mounts. Mounting a volume in shared mode does not restrict any other container to mount and make changes to that volume. This might be catastrophic if the mounted volume is sensitive to changes. Do not set mount propagation mode to shared until needed.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.19'
  tag 'cis-docker-1.13.0': '5.19'
  tag 'level:1'
  ref 'Capability to specify per volume mount propagation mode', url: 'https://github.com/docker/docker/pull/17034'
  ref 'Docker run reference', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'Shared Subtrees', url: 'https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt'

  docker.containers.running?.ids.each do |id|
    raw = command("docker inspect --format '{{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' #{id}").stdout
    describe raw.delete("\n").delete('\"').delete(' ') do
      it { should_not eq 'shared' }
    end
  end
end

control 'docker-5.20' do
  impact 1.0
  title 'Do not share the host\'s UTS namespace'
  desc 'UTS namespaces provide isolation of two system identifiers: the hostname and the NIS domain name. It is used for setting the hostname and the domain that is visible to running processes in that namespace. Processes running within containers do not typically require to know hostname and domain name. Hence, the namespace should not be shared with the host.

  Rationale: Sharing the UTS namespace with the host provides full permission to the container to change the hostname of the host. This is insecure and should not be allowed.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.20'
  tag 'cis-docker-1.13.0': '5.20'
  tag 'level:1'
  ref 'Docker run reference', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'namespaces - overview of Linux namespaces', url: ' http://man7.org/linux/man-pages/man7/namespaces.7.html'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig UTSMode]) { should_not eq 'host' }
    end
  end
end

control 'docker-5.21' do
  impact 1.0
  title 'Do not disable default seccomp profile'
  desc 'Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile disables 44 system calls, out of 313. It should not be disabled unless it hinders your container application usage.

  Rationale: A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of the applications do not need all the system calls and thus benefit by having a reduced set of available system calls. The reduced set of system calls reduces the total kernel surface exposed to the application and thus improvises application security.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.21'
  tag 'cis-docker-1.13.0': '5.21'
  tag 'level:1'
  ref 'New Docker Security Features and What They Mean: Seccomp Profiles', url: 'http://blog.aquasec.com/new-docker-security-features-and-what-they-mean-seccomp-profiles'
  ref 'Docker run reference', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'Seccomp default.json', url: 'https://github.com/moby/moby/blob/master/profiles/seccomp/default.json'
  ref 'Seccomp security profiles for Docker', url: 'https://docs.docker.com/engine/security/seccomp/'
  ref 'SECure COMPuting with filters', url: 'https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt'
  ref 'Capability to specify per volume mount propagation mode', url: 'https://github.com/moby/moby/pull/17034'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig SecurityOpt]) { should include(/seccomp/) }
      its(%w[HostConfig SecurityOpt]) { should_not include(/seccomp[=|:]unconfined/) }
    end
  end
end

control 'docker-5.22' do
  impact 1.0
  title 'Do not docker exec commands with privileged option'
  desc 'Do not docker exec with --privileged option.

  Rationale: Using --privileged option in docker exec gives extended Linux capabilities to the command. This could potentially be insecure and unsafe to do especially when you are running containers with dropped capabilities or with enhanced restrictions.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.22'
  tag 'cis-docker-1.13.0': '5.22'
  tag 'level:2'
  ref 'docker exec', url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep privileged').stdout do
    it { should be_empty }
  end
end

control 'docker-5.23' do
  impact 1.0
  title 'Do not docker exec commands with user option'
  desc 'Do not docker exec with --user option.

  Rationale: Using --user option in docker exec executes the command within the container as that user. This could potentially be insecure and unsafe to do especially when you are running containers with dropped capabilities or with enhanced restrictions. For example, suppose your container is running as tomcat user (or any other non-root user), it would be possible to run a command through docker exec as root with --user=root option. This could potentially be dangerous.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.23'
  tag 'cis-docker-1.13.0': '5.23'
  tag 'level:2'
  ref 'docker exec', url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep user').stdout do
    it { should be_empty }
  end
end

control 'docker-5.24' do
  impact 1.0
  title 'Confirm cgroup usage'
  desc 'It is possible to attach to a particular cgroup on container run. Confirming cgroup usage would ensure that containers are running under defined cgroups.

  Rationale: System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under docker cgroup by default. At run-time, it is possible to attach to a different cgroup other than the one that was expected to be used. This usage should be monitored and confirmed. By attaching to a different cgroup than the one that is expected, excess permissions and resources might be granted to the container and thus, can prove to be unsafe.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.24'
  tag 'cis-docker-1.13.0': '5.24'
  tag 'level:1'
  ref 'Specify custom cgroups', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'Chapter 1. Introduction to Control Groups (Cgroups)', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/ch01.html'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig CgroupParent]) { should be_empty }
    end
  end
end

control 'docker-5.25' do
  impact 1.0
  title 'Restrict container from acquiring additional privileges'
  desc 'Restrict the container from acquiring additional privileges via suid or sgid bits.

  Rationale: A process can set the no_new_priv bit in the kernel. It persists across fork, clone and execve. The no_new_priv bit ensures that the process or its children processes do not gain any additional privileges via suid or sgid bits. This way a lot of dangerous operations become a lot less dangerous because there is no possibility of subverting privileged binaries.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.25'
  tag 'cis-docker-1.13.0': '5.25'
  tag 'level:1'
  ref 'BLOG: No New Privileges support in docker', url: 'https://github.com/projectatomic/atomic-site/issues/269'
  ref 'Add support for NoNewPrivileges in docker', url: 'https://github.com/moby/moby/pull/20727'
  ref 'no_new_privs', url: 'https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt'
  ref 'System call filtering and no_new_privs', url: 'https://lwn.net/Articles/475678/'
  ref 'Add PR_{GET,SET}_NO_NEW_PRIVS to prevent execve from granting privs', url: 'https://lwn.net/Articles/475362/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig SecurityOpt]) { should include(/no-new-privileges/) }
    end
  end
end

control 'docker-5.26' do
  impact 1.0
  title 'Check container health at runtime'
  desc 'If the container image does not have an HEALTHCHECK instruction defined, use --health-cmd parameter at container runtime for checking container health.

  Rationale: One of the important security triads is availability. If the container image you are using does not have a pre-defined HEALTHCHECK instruction, use the --health-cmd parameter to check container health at runtime. Based on the reported health status, you could take necessary actions.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.26'
  tag 'cis-docker-1.13.0': '5.26'
  tag 'level:1'
  ref 'Add support for user-defined healthchecks', url: 'https://github.com/moby/moby/pull/22719'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its('State.Health.Status') { should eq 'healthy' }
    end
  end
end

control 'docker-5.27' do
  impact 1.0
  title 'Ensure docker commands always get the latest version of the image'
  desc 'Always ensure that you are using the latest version of the image within your repository and not the cached older versions.

  Rationale: Multiple docker commands such as docker pull, docker run, etc. are known to have an issue that by default, they extract the local copy of the image, if present, even though there is an updated version of the image with the "same tag" in the upstream repository. This could lead to using older and vulnerable images.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.27'
  tag 'cis-docker-1.13.0': '5.27'
  tag 'level:1'
  ref 'Modifying trusted/untrusted pull behavior for create/run/build', url: 'https://github.com/moby/moby/pull/16609'

  describe 'docker-test' do
    skip 'Ensure docker commands always get the latest version of the image'
  end
end

control 'docker-5.28' do
  impact 1.0
  title 'Use PIDs cgroup limit'
  desc 'Use --pids-limit flag at container runtime.

  Rationale: Attackers could launch a fork bomb with a single command inside the container. This fork bomb can crash the entire system and requires a restart of the host to make the system functional again. PIDs cgroup --pids-limit will prevent this kind of attacks by restricting the number of forks that can happen inside a container at a given time.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.28'
  tag 'cis-docker-1.13.0': '5.28'
  tag 'level:1'
  ref 'Add PIDs cgroup support to Docker', url: 'https://github.com/moby/moby/pull/18697'
  ref 'docker run', url: 'https://docs.docker.com/engine/reference/commandline/run/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its('HostConfig.PidsLimit') { should_not cmp 0 }
      its('HostConfig.PidsLimit') { should_not cmp(-1) }
    end
  end
end

control 'docker-5.29' do
  impact 1.0
  title 'Do not use Docker\'s default bridge docker0'
  desc 'Do not use Docker\'s default bridge docker0. Use docker\'s user-defined networks for container networking.

  Rationale: Docker connects virtual interfaces created in the bridge mode to a common bridge called docker0. This default networking model is vulnerable to ARP spoofing and MAC flooding attacks since there is no filtering applied.'

  tag 'do cker'
  tag 'cis-docker-1.12.0': '5.29'
  tag 'cis-docker-1.13.0': '5.29'
  tag 'level:2'
  ref 'narwhal – secure Docker networking', url: 'https://github.com/nyantec/narwhal'
  ref 'Analysis of Docker Security', url: 'https://arxiv.org/pdf/1501.02967.pdf'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'

  describe 'docker-test' do
    skip 'Not implemented yet'
  end
end

control 'docker-5.30' do
  impact 1.0
  title 'Do not share the host\'s user namespaces'
  desc 'Do not share the host\'s user namespaces with the containers.

  Rationale: User namespaces ensure that a root process inside the container will be mapped to a non-root process outside the container. Sharing the user namespaces of the host with the container thus does not isolate users on the host with users on the containers.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.30'
  tag 'cis-docker-1.13.0': '5.30'
  tag 'level:1'
  ref 'docker run', url: 'https://docs.docker.com/engine/reference/commandline/run/'
  ref 'Rooting out Root: User namespaces in Docker', url: 'https://events.linuxfoundation.org/sites/events/files/slides/User%20Namespaces%20-%20ContainerCon%202015%20-%2016-9-final_0.pdf'
  ref 'Phase 1 implementation of user namespaces as a remapped container root', url: 'https://github.com/moby/moby/pull/12648'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its('HostConfig.UsernsMode') { should eq '' }
    end
  end
end

control 'docker-5.31' do
  impact 1.0
  title 'Do not mount the Docker socket inside any containers'
  desc 'The docker socket (docker.sock) should not be mounted inside a container.

  Rationale: If the docker socket is mounted inside a container it would allow processes running within the container to execute docker commands which effectively allows for full control of the host.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.31'
  tag 'cis-docker-1.13.0': '5.31'
  tag 'level:1'
  ref 'The Dangers of Docker.sock', url: 'https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/'
  ref 'Docker-in-docker vs mounting /var/run/docker.sock', url: 'https://forums.docker.com/t/docker-in-docker-vs-mounting-var-run-docker-sock/9450/2'
  ref 'Is `-v /var/run/docker.sock:/var/run/docker.sock` a ticking time bomb', url: 'https://github.com/moby/moby/issues/21109'

  docker.containers.running?.ids.each do |id|
    docker.object(id).Mounts.each do |mount|
      describe mount do
        its('Source') { should_not include 'docker.sock' }
      end
    end
  end
end
