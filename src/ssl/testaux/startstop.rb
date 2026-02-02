Dir["makefile*"].each do |path|
  makefile = File.basename(path)
  ## make sure we don't use file with funny chars (back up etc...)
  if /[^_0-9a-zA-Z]/.match(makefile) then
    puts "Ignoring file #{path}"
  else
    system("make -f #{makefile} #{ARGV[0]}")
  end
end
