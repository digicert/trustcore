#################################################################################
# script to test the servers with the openssl TLS client                        #
#                                                                               #
# Copyright 2025 DigiCert Project Authors. All Rights Reserved.
# 
# DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
# - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
# - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
#   or https://www.digicert.com/master-services-agreement/
# 
# *For commercial licensing, contact DigiCert at sales@digicert.com.*
#                                                                               #
#################################################################################

require 'open3'
require 'socket'

####### utility function to verify server is up ####################

def wait_for_server( port)
  10.times do |i|
    begin
      s = TCPSocket.new 'localhost', port
      s.close
      return true # server is up
    rescue Exception => e
      puts Time.new.strftime("%H:%M:%S: ")  + e.message
      #wait 3 seconds and try again
      sleep(3)
    end
  end
  return false
end

########### IOT-606 ##############

LOCATIONS = %w{ /usr/bin /usr/bin/ssl /usr/local/bin /usr/local/ssl/bin /opt/bin /opt/ssl/bin }

# looks for openssl in the locations LOCATIONS,
# returns an hash where each version points to the full_path
def find_all_OpenSSL()

    all_OpenSSL = Hash.new

    LOCATIONS.each do | l |
        begin
            full_path = l + "/openssl"
            version = `#{full_path} version`
            numeric_version = version.split()[1]
            all_OpenSSL[numeric_version] = full_path
        rescue
        end
    end
    return all_OpenSSL
end

# returns the path of the most recent version
def most_recent_version(h)
  most_recent = nil
  max_num_version = 0
  release = ""
  h.each do | version, path |
    m = version.match(/(\d)\.(\d)\.(\d+)(\w*)/)
    if m
      num_version = m[1].to_i * 10000 +
                    m[2].to_i * 100 +
                    m[3].to_i
      if (num_version > max_num_version)
        max_num_version = num_version
        release = m[4]
        most_recent = path
      elsif num_version == max_num_version
        if (m[4] > release )
          release = m[4]
          most_recent = path
        end
      end
    end
  end
  return most_recent
end

# figure out the mocana ciphers by parsing cipherdesc.h
# returns a hash with cipherid -> minSSLVersion
def collect_mocana_ciphers()
  all_mocana_ciphers = Hash.new

  File.open("./cipherdesc.h").each do |line|
    m  = line.match(/CIPHER_DESC\(\s*0x(\h{4}),\s*\w+,\s*(\d+)\s*\)/)
    if (m)
      cipherId = m[1].upcase
      sslverMinor = m[2]
      all_mocana_ciphers[cipherId] = sslverMinor.to_i
    end
  end
  return all_mocana_ciphers
end

# figure out the openssl ciphers
# returns a hash with cipherid -> OpenSSL cipher name
def collect_openssl_ciphers(opensslPath)
  all_openssl_ciphers = Hash.new
  ciphers = `#{opensslPath} ciphers -V`
  ciphers.each_line do |line|
    m = line.match(/0x(\h{2}),0x(\h{2})\s*-\s*(\S+)\s*/)
    if m
      cipherId = m[1]+m[2].upcase
      cipherName = m[3]
      all_openssl_ciphers[cipherId] = cipherName
    end
  end
  return all_openssl_ciphers
end


# does one connection with the specified cipher and tls version to the mocana server
def testCipherAux(opensslPath, cipherId, cipherName, tlsVersion)
  exit_status = -1
  reply = ""
  Open3.popen2e("#{opensslPath} s_client #{tlsVersion} -cipher #{cipherName} -psk 101112131415161718191a1b1c1d1e1f -connect localhost:1443") do |stdin, stdout_err, wait_thr |
    stdin.print "GET / HTTP/1.0\r\n\r\n"
    reply = stdout_err.read
    exit_status = wait_thr.value.exitstatus
  end

  # look at the reply
  if (exit_status == 0)

    tlsMatch = ""
    case tlsVersion
    when "-tls1"
      tlsMatch = "TLSv1"
    when "-tls1_1"
      tlsMatch = "TLSv1.1"
    when "-tls1_2"
      tlsMatch = "TLSv1.2"
    end

    if (!reply.include?("Congratulations!"))
      exit_status = 1
      puts "#{__FILE__}:#{__LINE__} incorrect reply with cipher = 0x#{cipherId} (#{cipherName}) and tlsVersion = #{tlsVersion}"
    elsif (!reply.include?(tlsMatch))
      exit_status = 1
      puts "#{__FILE__}:#{__LINE__} tls version mismatch with cipher = 0x#{cipherId} (#{cipherName}) and tlsVersion = #{tlsVersion}"
    elsif (!reply.include?("0x"+cipherId))
      exit_status = 1
      puts "#{__FILE__}:#{__LINE__} cipher mismatch  with cipher = 0x#{cipherId} (#{cipherName}) and tlsVersion = #{tlsVersion}"
    end
  else
    puts "#{__FILE__}:#{__LINE__} error connecting with cipher = 0x#{cipherId} (#{cipherName}) and tlsVersion = #{tlsVersion}"
  end

  return exit_status
end


def testCipher( opensslPath, cipherId, cipherName, minTLSVersion)
  numErrs = 0

  cipherNum = cipherId.to_i(16)

  # filter out the SRP ciphers
  if (cipherNum  >= 0xC01A && cipherNum <= 0xC022)
    return 0
  end

  minTLSVersion = 1 if minTLSVersion < 1 # mocana server doesn't accept SSLv3 (test IOT-174 below)

  (minTLSVersion..3).each do |i|
    tlsVersion = ""
    case i
    when 1 then tlsVersion = "-tls1"
    when 2 then tlsVersion = "-tls1_1"
    when 3 then tlsVersion = "-tls1_2"
    else
      tlsVersion = ""
    end

    res = testCipherAux( opensslPath, cipherId, cipherName, tlsVersion)

    if (cipherNum == 0x0005) # negative test for ARC 4 and not SSLv3
      if (0 == res)
        numErrs += 1
      end
    else
      if (res != 0)
        numErrs += 1
      end
    end
  end

  return numErrs
end



# openssl client connecting to mocana server
def test_ciphers()
  numErrors = 0
  all_OpenSSL = find_all_OpenSSL()
  # try the one with the biggest version
  mostRecentOpenSSL = most_recent_version(all_OpenSSL)
  openssl_ciphers = collect_openssl_ciphers(mostRecentOpenSSL)
  mocana_ciphers = collect_mocana_ciphers()

  # make sure the Mocana SSL server is up
  if (false == wait_for_server(1443))
    puts "#{__FILE__}:#{__LINE__} cannot connect to Mocana SSL server"
    return 1
  end

  common_ciphers = openssl_ciphers.keys & mocana_ciphers.keys

  common_ciphers.each do | cipherId |
    numErrors += testCipher( mostRecentOpenSSL,
                             cipherId,
                             openssl_ciphers[cipherId],
                             mocana_ciphers[cipherId])
  end
  return numErrors
end

########## IOT-174 ########

# used by test_IOT_174
def ssl2ConnectionTest(port)
  exit_status = -1
  begin
    Open3.popen2e("openssl s_client -ssl2 -connect localhost:#{port}") do |stdin, stdout_err, wait_thr |
      stdin.print "GET / HTTP/1.0\r\n\r\n"
      reply = stdout_err.read
      exit_status = wait_thr.value.exitstatus
    end
  rescue
  end
  return exit_status
end

# verify that the SSL servers cannot connect using SSL v2 :-)
def test_IOT_174

  retVal = 0

  # verify that both servers are up -- otherwise meaningless test
  if (false == wait_for_server(1450))
    retVal += 1
    puts "#{__FILE__}:#{__LINE__} cannot connect to OpenSSL server"
    return retVal
  end

  if (false == wait_for_server(1443))
    retVal += 1
    puts "#{__FILE__}:#{__LINE__} cannot connect to Mocana SSL server"
    return retVal
  end

  if (0 != ssl2ConnectionTest(1450))
    retVal += 1
    puts "#{__FILE__}:#{__LINE__} cannot connect to OpenSSL using SSLv2"
  end

  if (0 == ssl2ConnectionTest(1443))
    retVal += 1
    puts "#{__FILE__}:#{__LINE__} can connect to Mocana SSL using SSLv2"
  end
  return retVal;

end

######### main ################

if RUBY_VERSION >= '1.9'
  ALL_TESTS = %w( test_IOT_174 test_ciphers )
else
  ALL_TESTS = %w()
end

selected_tests = nil
errors = 0
tests = 0

if ARGV.length > 0
  puts "select tests"
  ARGV.each do | arg |
    selected_tests = ALL_TESTS.select { |test | test =~ /^#{arg}/ }
  end
else
  puts "running all tests"
  selected_tests = ALL_TESTS
end

if selected_tests
  tests = selected_tests.length
  selected_tests.each do | test_name |
    test_errors = send(test_name)
    if (test_errors != 0)
      puts "(#{test_name}): Fail: #{test_errors} error(s)"
      errors += 1
    else
      puts "(#{test_name}): Pass"
    end
  end
end

## canonical summary message
puts "Pass:        #{tests-errors}"
puts "Fail:        #{errors}"
puts "Total tests: #{tests}"
exit(errors)
