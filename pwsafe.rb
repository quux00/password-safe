#!/usr/bin/env ruby
#
# # # # # # # # #
# /41/pws_2.rb
#
# by               Jan Lelis
# e-mail:          mail@janlelis.de
# type/version:    ruby
# snippet url:     http://rbJL.net/41/pws_2.rb
# original post:   http://rbJL.net/41-tutorial-build-your-own-password-safe-with-ruby
# license:         CC-BY (DE)
#
# (c) 2010 Jan Lelis.
# ----------- Updated Version ----------- #
# Additional Notes and Mods from Michael Peterson
#
# TODO:
#  1. Add more sophisticated fuzzy matching
#  2. Add YAML formatter for the filedump format
#  X. Check that the -s --safe option works
#  X. Add 'read entries from file' option
#  X. Add 'stty -raw' option to keep passwords from being displayed
#     but only for the PasswordSafe password, not the entries
#  X. Add option to change the safe password
#  X. Check for duplicate entries when new added
#  8. Be able to take more than one command line switch at once (such as -d, then -l)
#  X. Be able to add in a password hint
# XX. Randomize the initialization vector (IV) - store it in the file
# 11. Write a version that integrates with GPGME library 
# XX. Add ability to get all entries (from -l or --listfull) that start with a certain
#     prefix/string
# 13. Refactor into more testable methods/classes and write unit tests
# 14. If no cmd-line options specified, it asks for the password from the user
#     before catching this error and reporting it - shouldn't prompt
#
require 'openssl'
require 'fileutils'
require 'optparse'
require 'pp'
#DEBUG
require 'pry'
#END DEBUG

def parse_options
  options = {}
  optparse = OptionParser.new  do |opts|
    opts.banner = "Usage: pwsafe.rb [OPTIONS]\n"

    # define the options
    options[:safepath] = nil
    opts.on('-s', '--safe [FILE]', 'Path to Password Safe (default: ~/.pws)') do |x|
      options[:safepath] = x
    end

    options[:add] = false
    opts.on('-a', '--add', 'Add to the Password Safe') do
      options[:add] = true
    end

    options[:addmany] = false
    opts.on('--addmany', 'Add multiple entries to the Password Safe') do
      options[:addmany] = true
    end

    options[:filedump] = false
    opts.on('-f', '--filedump [FILE]', 'Dump password entries to file') do |x|
      options[:filedump] = x || true
    end

    options[:list] = false
    opts.on('-l', '--list [PATTERN]', 
            'List all names/keys. Pattern with wildcard asterisks can be used: -l "pa*"') do |x|
      options[:list] = x || true
    end

    lf_msg = 'List all entries in full: entryname, key and password. Optionally, limit output with PATTERN.' 
    options[:listfull] = false
    opts.on('--listfull [PATTERN]', lf_msg) do |x|
      options[:listfull] = x || true
    end

    opts.on('-g', '--get val|PATTERN',
            'Show entry associated with the entry "val". Can use wildcard "*" in the PATTERN') do |x|
      options[:listfull] = x
    end

    options[:update] = nil
    opts.on('-u', '--update val',
            'Update/Change password associated with the name "val"') do |x|
      options[:update] = x
    end

    options[:delete] = nil
    opts.on('-d', '--delete val',
            'Delete name/password entry associated with the name "val"') do |x|
      options[:delete] = x
    end

    options[:chg_password] = false
    opts.on('-c', '--change-safe-password',
            'Change the safe password') do |x|
      options[:chg_password] = true
    end

    options[:load_from_file] = nil
    opts.on('-r', '--read FILE', 'Read/load entries from plaintext file') do |x|
      options[:load_from_file] = x
    end

    options[:get_hint] = false
    opts.on('-t', '--hint', 'Get password hint') do
      options[:get_hint] = true
    end

    options[:set_hint] = false
    opts.on('-n', '--set-hint', 'Set/change password hint') do
      options[:set_hint] = true
    end

    # help screen
    opts.on('-h', '--help', 'Display this screen') do
      puts opts
      exit
    end  # end OptionParser.new block
  end

  # parse ARGV, removing any options and their params
  begin
    optparse.parse!
  rescue SystemExit => se   # calling exit raises a SystemExit exception
    exit
  rescue Exception => ex
    $stderr.puts "ERROR: Incorrect command line options: #{ex.class}"
    exit
  end
  return optparse, options
end  # parse_options()


PASSWORD_SAFE_FILE = File.expand_path('~/.pws')


# --------------------- #
# ---[ MAIN METHOD ]--- #
# --------------------- #

def main

  optparse, options = parse_options
  ARGV.pop while ARGV.length > 0  # have to clear command line before reading from STDIN

  password_safe_file = options[:safepath] || PASSWORD_SAFE_FILE

  if options[:set_hint]
    PasswordSafe.set_hint( password_safe_file, prompt_for_hint() )
    exit

  elsif options[:get_hint]
    ht = PasswordSafe.hint(password_safe_file)
    if not ht or ht == ''
      puts "No hint has been set"
    else
      puts ht
    end
    exit  #~TODO: remove these exit's later ...
  end

  # get the password from the user - and get a confirmation
  # (enter twice) if the safe does not yet exist and needs to
  # be created
  b_safe_exists = File.file?(password_safe_file)
  password = prompt_for_safe_password(!b_safe_exists)
  # on linux need to do a "puts" after doing an stty for some reason - 
  #   next output gets indented without it
  puts
  pws = PasswordSafe.new( password, password_safe_file )

  if options[:add] or options[:addmany]
    ar_entries = []

    print 'Enter data to encrypt: '
    new_data = gets.chop.strip
    pws.validate_entry(new_data)

    entryname = new_data.split(':')[0]
    if pws.has_entry?( entryname )
      print "Entry for '#{entryname}' already exists in the safe. Proceed? (Y/n): "
      exit if gets.chomp.strip =~ /^n/i
    end
    ar_entries << new_data

    if options[:addmany]
      while true
        print "Enter data to encrypt ('d' when done): "
        new_data = gets.chop.strip
        break if new_data == 'd'
        pws.validate_entry(new_data)

        entryname = new_data.split(':')[0]
        if pws.has_entry?( entryname )
          print "Entry for '#{entryname}' already exists in the safe. Proceed? (Y/n): "
          next if gets.chomp.strip =~ /^n/i
        end
        ar_entries << new_data
      end
    end

    pws.add_to_safe(ar_entries)

  elsif options[:list] or options[:listfull]

    # create options hash for the pws#list method
    list_opts = {}
    if options[:list]
      list_opts[:what] = :name
      if options[:list].is_a? String
        list_opts[:pattern] = options[:list]
      end
    else
      list_opts[:what] = :all
      if options[:listfull].is_a? String
        list_opts[:pattern] = options[:listfull]
      end
    end

    ar_entries = pws.list(list_opts)

    puts "Entries:"
    if ar_entries
      ar_entries.each do |e|
        puts ' * ' + e
      end
    else
      puts "  None (safe is empty)"
    end

  elsif options[:update]
    if pws.has_entry?(options[:update])
      # get new username
      while true
        print " #{options[:update]} Username/Id : "
        uname = gets.chomp.strip
        if uname == '' or uname.include?(':')
          puts "Invalid Username/Id: cannot be blank or include colons (':'). Try again."
        else
          break
        end
      end

      # get new password
      while true
        print " #{options[:update]} Password    : "
        pw = gets.chomp.strip
        if pw == '' or pw.include?(':')
          puts "Invalid Password: cannot be blank or include colons (':'). Try again."
        else
          break
        end
      end

      pws.update(options[:update], uname, pw)
    else
      $stderr.puts "No entry name match for '#{options[:update]}'"
    end

  elsif options[:delete]
    if pws.has_entry?(options[:delete])
      pws.delete(options[:delete])
    else
      $stderr.puts "No entry name match for '#{options[:delete]}'"
    end

  elsif options[:filedump]
    dumpfile = File.expand_path("~/.pws.txt");
    if options[:filedump].is_a? String
      dumpfile = options[:filedump]
    end
    pws.dump_to_file(dumpfile)
    puts "Password safe written in plaintext to #{dumpfile}"

  elsif options[:load_from_file]
    loadfile = options[:load_from_file]
    nadded = pws.load_from_file(loadfile)
    if nadded == 1
      puts "1 new entry from '#{loadfile}' has been merged into the Password Safe"
    else
      puts "#{nadded} new entries from '#{loadfile}' have been merged into the Password Safe"
    end

  elsif options[:chg_password]
    pws.change_safe_password(  prompt_for_safe_password(true) )

  else
    # to get the help screen printed, set the -h option artificially and call
    # parse on OptionParser
    $stderr.puts "ERROR: no valid command line option specified"
    optparse.getopts(['-h'])
    optparse.parse
  end

rescue BadPassword => bp
  $stderr.puts "  ERROR: Wrong password"
rescue InvalidEntry => ie
  $stderr.puts "  ERROR: #{ie}"
end


def prompt_for_hint
  while true
    print "Enter password hint: "
    hint = STDIN.gets.chomp.strip
    if hint == ''
      puts "Invalid hint. Try again"
    else
      return hint
    end
  end
end

def prompt_for_safe_password(b_new = false)
  # get the password key from the user
  passwd = nil
  prompt = (b_new ? "Enter new password for safe: " : "Enter password for safe: ")
  begin
    # save previous state of stty
    old_state = `stty -g`
    system "stty raw -echo"

    until (passwd)
      print prompt
      passwd = ''
      passwd = read_hidden_input
      if b_new
        print "Confirm password: "
        confpw = read_hidden_input
        if (passwd != confpw)
          passwd = nil
          puts "ERROR: Passwords do not match.  Try again."
        end
      end
    end  # end until loop
    passwd

  rescue => ex
    puts "#{ex.class}: #{ex.message}"
    puts ex.backtrace

  ensure
    # restore previous state of stty
    system "stty #{old_state}"
  end
end

#
# Reads one char at a time from STDIN while in
# stty raw -echo mode, in which typed chars are not
# visible and you have to explicitly capture an
# Enter/Return entry to know when to quit reading
#
# @return string - input from user
#
def read_hidden_input
  input = ''
  while true
    c = STDIN.getc.chr
    if c == "\r" or c == "\n" then puts; break; end
    input << c
  end
  input.strip
end



# ---------------------------- #
# ---[ PasswordSafe Class ]--- #
# ---------------------------- #

#
# Substantially enhanced and partially redesigned by Michael Peterson
# but based on the class from Jan Lelis
#
class PasswordSafe
  VERSION = '0.1.0'.freeze
  INIT_ENTRY = 'init'
  CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


  # pwdata is the holder of the data - it is an array of "triples"
  # of the format token1:token2:token3
  attr_accessor :pwdata


  ##############################################
  # CLASS METHODS
  ##############################################

  #
  #
  #
  #
  def self.hint(safe_path)
    while hint_line = DATA.readline.chomp.strip
      return $1 if hint_line =~ /#{safe_path}\s*=\s*(.+)\s*/
    end
  rescue EOFError => eof
    nil
  end

  #
  #
  #
  #
  def self.set_hint(safe_path, user_hint)
    pos = DATA.pos                     # memorize position after __END__
    hints = DATA.read                  # read what's currently there
    DATA.reopen(__FILE__, "a+")        # turn on writing/append mode
    DATA.truncate(pos)                 # remove the DATA section
    hints.each_line do |line|          # update DATA
      DATA.puts line unless line =~ /#{safe_path}\s*=/
    end
    DATA.puts "#{safe_path}=#{user_hint}"
  end


  ##############################################
  # INSTANCE METHODS
  ##############################################

  def initialize( password, filename = File.expand_path('~/.pws') )
    @pwfile = filename
    @pwdata = INIT_ENTRY

    # hash the password for later use by the Encryptor module
    @pwhash = Encryptor.hash(password)

    create_safe
    read_safe
  end

  def validate_entry(entry)
    if entry.split(':').size < 3
      raise InvalidEntry.new("Invalid entry - must have three fields separated by colons (':')")
    end
  end

  def has_entry?(entryname)
    @pwdata.match(/\n#{entryname}:/) or @pwdata.match(/^#{entryname}:/)
  end

  def delete(entryname)
    ar_entries = @pwdata.split("\n")
    @pwdata = ''
    ar_entries.each do |e|
      next if e.strip == ''
      unless e.start_with?("#{entryname}:")
        @pwdata << "#{e}\n"
      end
    end
    # no newline on the last entry
    @pwdata.chomp
    write_safe
  end

  def update(entryname, uname, password)
    ar_entries = @pwdata.split("\n")
    @pwdata = ''
    ar_entries.each do |e|
      next if e.strip == ''
      #~TODO: could do fuzzy match later if desired
      if e.start_with?("#{entryname}:")
        @pwdata << "#{entryname}:#{uname}:#{password}\n"
      else
        @pwdata << "#{e}\n"
      end
    end
    # no newline on the last entry
    @pwdata.chomp
    write_safe
  end


  # Loads other triples from a plaintext file and merges new entries
  # (based on matching the first token in a case-insenstive manner)
  # into the main Password Safe file
  # 
  # @param [String] fname file with plaintext triples to be added
  # @return [Number] returns number of new (unique) entries added to the
  #         password safe
  def load_from_file(fname)
    # first load plaintext file into memory
    ary_newdata = ''
    ary_pwdata = @pwdata.split "\n"
    File.open(fname) do |f|
      ary_newdata = f.readlines.reject do |e|
        match = e.match(/([^:]+):[^:]+:[^:]+/)
        tok1 = (match ? match[1] : nil)
        tok1 == nil || ary_pwdata.find { |d| d =~ /^#{tok1}/i }
      end
    end
    # readlines leaves newlines, remove since add_to_safe doesn't expect them
    ary_newdata.map! { |e| e.chomp }
    # encrypt and save new safe contents
    add_to_safe(ary_newdata)
    ary_newdata.size
  end


  def safe_exists?
    File.file?(@pwfile)
  end

  def change_safe_password(password)
    read_safe
    @pwhash = Encryptor.hash(password)
    write_safe
  end

  # Adds one or more new entries to the safe and then writes the safe
  # 
  # @param [Array<String> or String] data array of strings, where string is
  #        of pwsafe format token:token:token
  # @return void
  def add_to_safe(data)
    [*data].each do |ent|
      unless ent and ent =~ /[^:]+:[^:]+:[^:]+/
        raise InvalidEntry.new("Data passed to add_to_safe does not match accepted format")
      end
      if @pwdata == INIT_ENTRY
        @pwdata = ent
      else
        @pwdata << "\n"
        @pwdata << ent
      end
    end  # end loop over data Enumerable
    write_safe
  end


  # right now this just does case-insenstive, and some primtive fuzzy matching
  # but can add real fuzzy matching logic - in the future - need to upgrade
  # to Ruby 1.9 to use the fuzzy-string-match gem
  #
  # @param input - the entry string to match
  # @param match_against - either a string or array with target values to match
  # @return - nil if no match
  #           index of match if match (if match_against is a string, and it
  #           matches the input, then it will return 0 (first 'index')
  def fuzzy_match( input, match_against )
    [*match_against].each_with_index do |targ, idx|
      if input =~ /^#{targ}$/i
        return idx
      elsif input.slice(0..5) =~ /^#{targ.slice(0..5)}/i
        return idx
      end
    end
    return nil

  end

  def dump_to_file(fname, formatter = self )
    File.open(fname, 'w') do |f|
      f.write( formatter.format_safe_contents(@pwdata) )
    end
  end


  def format_safe_contents(pwdata)
    pwdata.chomp
    pwdata << "\n"
    pwdata  #~TODO: hopefully don't need this last line - test, then remove
  end


  # Lists entries in the Password Safe to STDOUT
  # The output can be limited in two ways:
  # 1. The user can ask for just the name (first token of the triple), not the full entry
  # 2. The user can limit the rows returned by passing a pattern string for the name 
  #    (using '*' as a wildcard token)
  # 
  # @param [Hash] opts the options to specify the desired output
  # @option opts [String/Symbol] :what what to show values allowed are :name or :all. Required.
  # @option opts [String/Symbol] :pattern user specified pattern to limit rows. Optional.
  # @return [Array<String>] array of entries matching the user's request
  def list(options)
    ar_lines = @pwdata.split("\n")

    # if only has INIT_ENTRY, then don't display to user - just tell
    # him the safe is empty
    return nil if ar_lines.size == 1 and ar_lines[0] =~ /^#{INIT_ENTRY}\s*$/

    if options[:pattern]
      str = options[:pattern].gsub(/\*/, '[^:]*')
      re = /^#{str}/i
      ar_lines.select! { |e| re.match(e) }
    end

    if options[:what] == :name
      ar_entries = ar_lines.map do |entry|
        ar_toks = entry.split(':')
        tok = ar_toks[0]
        if ar_toks.size > 3
          tok = ar_toks[0...-2].join(':')
        end
        tok
      end
      return ar_entries.sort{|a,b| a.casecmp b}
    else
      return ar_lines.sort{|a,b| a.casecmp b}
    end
  end  # end list()


  private


  # Tries to load and decrypt the password safe from the pwfile
  # @raises BadPassword - if it cannot be read (Encryptor module does this)
  def read_safe
    pwdata_enc_base64 = File.read(@pwfile)
    pwdata_encrypted = pwdata_enc_base64.unpack('m')[0] # fix for Ruby 1.9 also works with 1.8
                                                        # was: unpack('m*').to_s
    # the cryptographic initialization vector is the first 32 chars of the unpacked string
    Encryptor.iv = pwdata_encrypted[0...32]
    pwdata_encrypted = pwdata_encrypted[32..-1]
    @pwdata = Encryptor.decrypt(pwdata_encrypted, @pwhash)
  end


  # Tries to encrypt and save the password safe into the pwfile
  def write_safe
    @pwdata.gsub!(/\n+/, "\n")  # try to remove any "empty entries"
    Encryptor.iv = create_random_IV
    pwdata_encrypted = Encryptor.encrypt(@pwdata, @pwhash)

    # add the initialization-vector to the start of the string to be 
    # base64 translated and saved to file
    pwdata_encrypted = Encryptor.iv + pwdata_encrypted

    # use pack with 'm*' to translate the encrypted bytes into base64
    # for better / easier to read storage on file
    pwdata_enc_base64 = [pwdata_encrypted].pack('m*')
    File.open( @pwfile, 'w' ){ |f| f.write pwdata_enc_base64 }

    # read_safe is here to check that the file just written is openable
    # with the password the user typed in (not corrupted)
    # if it's not corrupted, then make a backup copy of it
    read_safe
    FileUtils.copy( @pwfile, "#@pwfile.bak" )
  end


  # Creates a random Initialization Vector (IV) of 32 characters long
  # for use in encrypting the password safe
  # 
  # @return [String] 32 character random string matching: \w{32}
  def create_random_IV
    iv = ''
    32.times do
      iv << CHARS[ rand(CHARS.length) ]
    end
    iv
  end


  # Checks if the file is accessible or create a new one
  def create_safe
    if !File.file? @pwfile
      puts "No password safe detected, creating one at #@pwfile"
      FileUtils.touch @pwfile
      write_safe
    end
  end

  ####################################################################
  #
  # Encryptor module the uses the OpenSSL::Cipher class to do the
  # encrypting/decrypting
  #
  # Original code from Jan Lelis
  # Not sure why he used an embedded eigenclass module for this
  # Something to research...
  #
  ####################################################################
  class << Encryptor = Module.new
    CIPHER = 'aes-256-cbc'

    def iv=(iv)
      @iv = iv
    end

    def iv  #~TODO: change to attr_accessor for the class later ...
      @iv
    end

    def decrypt( data, pwhash )
      crypt :decrypt, data, pwhash
    end

    def encrypt( data, pwhash )
      crypt :encrypt, data, pwhash
    end

    def hash( plaintext )
      OpenSSL::Digest::SHA512.new( plaintext ).digest
    end

    private

    # Encrypts or decrypts the data with the password hash as key
    def crypt( decrypt_or_encrypt, data, pwhash )
      unless @iv
        raise RuntimeError, 
          "Initialization Vector (iv) must be set before doing #{decrypt_or_encrypt}"
      end

      begin
        cipher = OpenSSL::Cipher.new(CIPHER)
        cipher.send decrypt_or_encrypt.to_sym
        cipher.key = pwhash
        cipher.iv = @iv
        cipher.update( data ) << cipher.final

      rescue OpenSSL::Cipher::CipherError => ce
        $stderr.puts ce
        $stderr.puts ce.inspect
        raise BadPassword.new

      rescue Exception => e
        puts "ERROR: Unable to #{decrypt_or_encrypt}: #{e.class}: #{e}"
        raise e
      end
    end  # end crypt()
  end    # end Encryptor eigenmodule
end      # end class PasswordSafe


class BadPassword < StandardError; end

class InvalidEntry < StandardError; end



if __FILE__ == $0
  main()
end


__END__
c:/Users/Petermi1/home/.pws=Cure-Rockford
/home/midpeter444/.pws=Cure-Rockford
