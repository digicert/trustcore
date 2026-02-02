##################################################
# conv.rb
#
# Copyright (c) 2007 Mocana
# Proprietary and Confidential
# All Rights Reserved 
#
# converts NIST test vector files for SHA (Short
# Msg) to C data structures
#
# Ex:
# cat SHA224ShortMsg.txt | ruby conv.rb > SHA224_test.txt
#   
###################################################

while line = gets
  line.chomp!
  if line =~ /^Len = / then
    print "{ ", line[6..line.length], ", "
  elsif line =~ /^Msg = / then
    print " \""
    print line[6..line.length].gsub(/([[:xdigit:]]{2})/, '\\x0\1')
    puts "\","
  elsif line =~ /^MD = / then
    print " \""
    print line[5..line.length].gsub(/([[:xdigit:]]{2})/, '\\x0\1')
    puts "\" },"  
  end
end
