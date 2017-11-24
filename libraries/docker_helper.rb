# encoding: utf-8

# Copyright 2016, Christoph Hartmann
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

class DockerHelper < Inspec.resource(1)
  name 'docker_helper'

  desc "
    A resource to retrieve information about docker
  "

  def path
    cmd = inspec.command('systemctl show -p FragmentPath docker.service')
    return nil if cmd.exit_status.to_i.nonzero?

    # parse data
    params = parse_systemd_values(cmd.stdout.chomp)

    # return the value
    params['FragmentPath']
  end

  def socket
    cmd = inspec.command('systemctl show -p FragmentPath docker.socket')
    return nil if cmd.exit_status.to_i.nonzero?

    # parse data
    params = parse_systemd_values(cmd.stdout.chomp)

    # return the value
    params['FragmentPath']
  end

  def overlay_networks
    cmd = inspec.command('docker network ls -f driver=overlay -q')
    return nil if cmd.exit_status.to_i.nonzero?

    # parse data from docker network ls
    params = parse_systemd_values(cmd.stdout.chomp)

    # parse data from docker network inspect output
    params.each do |k, _v|
      params[k] = parse_network_values(inspec.command("docker network inspect #{k}").stdout.delete('\"').delete(',').chomp)
    end

    # return the value
    params
  end

  private

  # returns parsed params
  def parse_systemd_values(stdout)
    SimpleConfig.new(
      stdout,
      assignment_regex: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/,
      multiple_values: false
    ).params
  end

  # returns parsed params
  def parse_network_values(stdout)
    SimpleConfig.new(
      stdout,
      assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/,
      multiple_values: false
    ).params
  end
end
