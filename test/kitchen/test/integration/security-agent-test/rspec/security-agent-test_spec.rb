require 'fileutils'
require 'kernel_out_spec_helper'
require 'open3'

GOLANG_TEST_FAILURE = /FAIL:/

def check_output(output, wait_thr, tag="")
  test_failures = []

  output.each_line do |line|
    striped_line = line.strip
    puts KernelOut.format(striped_line, tag)
    test_failures << KernelOut.format(striped_line, tag) if line =~ GOLANG_TEST_FAILURE
  end

  if test_failures.empty? && !wait_thr.value.success?
    test_failures << KernelOut.format("Test command exited with status (#{wait_thr.value.exitstatus}) but no failures were captured.", tag)
  end

  test_failures
end

print KernelOut.format(`cat /etc/os-release`)
print KernelOut.format(`uname -a`)

describe 'functional test running directly on host' do
  it 'successfully runs' do
  end
end

if File.readlines("/etc/os-release").grep(/SUSE/).size == 0 and !File.exists?('/etc/rhsm')
  describe 'functional test running inside a container' do
    it 'successfully runs' do
      Open3.popen2e("sudo", "docker", "exec", "-e", "DD_SYSTEM_PROBE_BPF_DIR=/tmp/security-agent/ebpf_bytecode", "docker-testsuite", "/tmp/security-agent/testsuite", "-test.v", "-status-metrics", "--env", "docker") do |_, output, wait_thr|
        test_failures = check_output(output, wait_thr, "d")
        expect(test_failures).to be_empty, test_failures.join("\n")
      end
    end
  end
end
