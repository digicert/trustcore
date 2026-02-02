#!/bin/ruby
#
# unittest.rb
#
# Copyright 2025 DigiCert Project Authors. All Rights Reserved.
# 
# DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
# - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
# - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
#   or https://www.digicert.com/master-services-agreement/
# 
# For commercial licensing, contact DigiCert at sales@digicert.com.*
#
# This script will build a main.c file to run all the unit tests in a directory

require 'pathname'


# Lets us refine down the number of test sources we want to include by giving 
# cproto the concept of include dirs.  Without this the globbing is more fuzzy 
# and just includes everything
if ARGV.length == 4
  # Dir of this file
  m_unit_test_dir = File.expand_path(File.dirname(__FILE__))
  m_mss_dir = File.expand_path(m_unit_test_dir + '/..')
  # Start building the include-path for cproto
  m_include_dirs = Array.new
  m_include_dirs.push('-I ' + m_mss_dir + '/src')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/common')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/asn1')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/platform')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/crypto')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/crypto/pqc')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/crypto_interface')
  m_include_dirs.push('-I ' + m_mss_dir + '/src/data_protection')
  m_include_dirs.push('-I ' + m_mss_dir + '/thirdparty/bssl/include')
  m_include_dirs.push('-I ' + m_mss_dir + '/thirdparty/wolfssl-5.7.2/')

  $m_includes_str = ""
  m_include_dirs.each do |item|
    $m_includes_str = $m_includes_str + ' ' + item
  end
end

#########################
# This function collects all the function that match the prototype
# specified
def collect_functions(fileName, opts)
  is_windows = (ENV['OS'] == 'Windows_NT')
  result = Array.new
  funPrefix = File.basename(fileName, File.extname(fileName))
  puts "\n/*============#{fileName}===========*/\n\n"
  re = Regexp.new("int\\s*(" + funPrefix + "\\w*)\\s*\\(")
  # use cproto to collect the prototypes
  out_dir = "/dev/null"
  if is_windows
    out_dir = "nul"
  end

  # Continuation of the include dir logic mentioned above. Use our include dirs 
  # in the call to cproto
  if ARGV.length == 4
    if opts.nil?
      prototypes = `cproto -E cpp #{$m_includes_str} -O #{out_dir} #{fileName}`.split("\n")
    else
      prototypes = `cproto #{opts} -E cpp #{$m_includes_str} -O #{out_dir} #{fileName}`.split("\n")
    end
  else
    if opts.nil?
      prototypes = `cproto -E cpp -O #{out_dir} #{fileName}`.split("\n")
    else
      prototypes = `cproto #{opts} -E cpp -O #{out_dir} #{fileName}`.split("\n")
    end
  end

  prototypes.each do |prototype|
    if md = re.match(prototype)
      puts "/* found #{prototype} ====> function is #{md[1]} */"
      result.push(md[1]) # store the function name
    end
  end
  puts "/*==================================*/\n\n"
  return result
end # collect_functions


#########################


if ARGV.length == 0
  puts "Please specify a directory"
  return 2
end

## Get the host id from the args
hostid = ARGV[1]
opts = ARGV[2]

## Get the list of test sources if available
if ARGV.length == 4
  test_srcs_list = Array.new
  File.readlines(ARGV[3]).each do |line|
    # Do not include commented lines
    unless line.to_s.start_with?('#')
      test_srcs_list.push(line.to_s)
    end
  end
else
  test_srcs_list = nil
end

# Get just the basename of the test sources
unless test_srcs_list.nil?
  test_srcs_list.map! { |src| './' + File.basename(src).delete("\n") }
end

# header -- add more
puts "/* main.c \n*\n* test driver generated on #{Time.now} \n*/\n\n"
unit_test_path = Pathname.new("../../../unit_tests")
src_path = Pathname.new(ARGV[0])
rel_path = unit_test_path.relative_path_from(src_path)

puts "#if defined(__RTOS_WIN32__)"
puts "#include \<winsock2.h\>\n"
puts "#pragma comment(lib,\"ws2_32.lib\")\n"
puts "#endif"

puts "#ifdef __UNITTEST_REMOTE_SUPPORT__"
puts "#include \<sys/types.h\>\n"
puts "#include \<sys/socket.h\>\n"
puts "#endif"

puts "#include \"#{rel_path}/unittest.h\"\n\n"

fileFuns = Hash.new

# C files
Dir[ARGV[0]+"/*_test.c"].each do |path|
  # read the file and look for functions like "int fileName_test_xyz()"
  if test_srcs_list.nil?
    fileFuns[File.basename(path)]= collect_functions(path, opts)
  else
    # If we have populated the test_srcs list then its a subset test so only
    # collect functions if its in test_srcs
    if test_srcs_list.include? path
      fileFuns[File.basename(path)]= collect_functions(path, opts)
    end
  end
end

# C++ files
Dir[ARGV[0]+"/*_test.cpp"].each do |path|
  # read the file and look for functions like "int fileName_test_xyz()"
  fileFuns[File.basename(path)]= collect_functions(path, opts)
end

# prototype
fileFuns.each_key do |fileName|
  puts "\n\n/* functions in file #{fileName} */"
  puts fileFuns[fileName].map { |f| "int #{f}();" }.join("\n")
  puts "\n"
end

# TestDescriptors
puts <<EOTD
TestDescriptor gTestDescs[] = {
EOTD
fileFuns.each_key do |fileName|
  fileFuns[fileName].each do |function|
    puts "\n\tTEST_DESC(\"#{fileName}\", #{function}),"
  end
end

# main

puts <<EOH
};

#define SECS_TO_WAIT_FOR_TARGET 60
int main_host(int argc, char* argv[])
{
  int retVal = 0;
  int pass = 0;
  int connfd = 0;
  int totalTests = sizeof(gTestDescs)/sizeof(gTestDescs[0]) ;

  retVal = CONNECT_TEST_TARGET_H("#{hostid}", "test", argc, argv, SECS_TO_WAIT_FOR_TARGET, &connfd);
  if (retVal != 0)
      return retVal;

  if ( argc > 1)
  {
     totalTests = 0;
     retVal = RUN_TEST_BY_NAMES_H( connfd, (const char**)argv+1, argc-1, gTestDescs,
              sizeof(gTestDescs)/sizeof(gTestDescs[0]), &pass, &totalTests);
  } else
  {
EOH

fileFuns.each_key do |fileName|
  fileFuns[fileName].each do |function|
    puts "\n\tretVal += RUN_TEST_H( connfd, \"#{fileName}\", #{function}, &pass);"
  end
end
puts <<EOT
  }

  STOP_TEST_TARGET_H(&connfd, 1);

  report(totalTests, pass);
  return retVal;
}

#ifdef __UNITTEST_REMOTE_RUNTARGET__
int main_target(int argc, char* argv[])
{
  int retVal = 0;
  int connfd = 0;
  struct sockaddr hostip = { 0 };

  retVal = INITCOMM_TGT(&hostip, &connfd);
  if (retVal != 0)
      return retVal;

  retVal = PROC_RUNTEST_CMDS_TGT(&hostip, connfd, gTestDescs, sizeof(gTestDescs)/sizeof(gTestDescs[0]) );

  STOPCOMM_TGT(&connfd, retVal);

  return retVal;
}
#endif

int main(int argc, char* argv[])
{

#ifdef __UNITTEST_REMOTE_RUNTARGET__
  return main_target(argc,argv); /* run the Target. */
#else
  return main_host(argc,argv); /* run the Host. */
#endif

}

EOT