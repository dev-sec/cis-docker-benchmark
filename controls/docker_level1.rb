# encoding: utf-8
# copyright: 2015, The Authors
# license: All rights reserved

title 'CIS Docker Benchmark Level 1'

control 'cis-docker-1.1' do
  impact 1.0
  title 'Create a separate partition for containers'
  desc 'All Docker containers and their data and metadata is stored under /var/lib/docker directory. By default, /var/lib/docker would be mounted under / or /var partitions based on availability.'
  ref 'http://www.projectatomic.io/docs/docker-storage-recommendation/'
  describe mount('/var/lib/docker') do
    it { should be_mounted }
  end
end

control 'cis-docker-1.2' do
  impact 1.0
  title 'Use the updated Linux Kernel'
  desc 'Docker in daemon mode has specific kernel requirements. A 3.10 Linux kernel is the minimum requirement for Docker.'
  ref 'https://docs.docker.com/engine/installation/binaries/#check-kernel-dependencies'
  ref 'https://docs.docker.com/engine/installation/#installation-list'

  kernel_version = command('uname -r').stdout
  kernel_compare = Gem::Version.new('3.10') < Gem::Version.new(kernel_version)

  describe kernel_compare do
    it { should eq true }
  end
end
