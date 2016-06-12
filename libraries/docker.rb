require 'yaml'

class Docker < Inspec.resource(1)
  name 'docker'

  desc "
    A resource to retrieve information about docker
  "

  # return a list on container ids
  def ps
    inspec.command('docker ps --format "{{.ID}}"').stdout.split
  end

  def inspect(id)
    raw = inspec.command("docker inspect #{id}").stdout
    info = inspec.json('').parse(raw)
    info[0]
  end

  def path
    cmd = inspec.command('systemctl show -p FragmentPath docker.service')
    return nil if cmd.exit_status.to_i != 0

    # parse data
    params = parse_systemd_values(cmd.stdout.chomp)

    # return the value
    params["FragmentPath"]
  end

  def socket
    cmd = inspec.command('systemctl show -p FragmentPath docker.socket')
    return nil if cmd.exit_status.to_i != 0

    # parse data
    params = parse_systemd_values(cmd.stdout.chomp)

    # return the value
    params["FragmentPath"]
  end

  private

  # returns parsed params
  def parse_systemd_values(stdout)
    SimpleConfig.new(
      stdout,
      assignment_re: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/,
      multiple_values: false,
    ).params
  end
end
