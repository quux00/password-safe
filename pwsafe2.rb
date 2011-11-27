#!/usr/bin/env ruby

# Second version of a "password safe".  This is intended to be used as a
# command line program on a machine with Ruby 1.9, the gpgme ruby gem
# installed, which requires GnuPG (gpg) installed plus the gpgme C library.
# It does symmetric encryption on data in memory and writes that encrypted
# data to file.  When opened, it prompts for a password and opens the
# password safe, unencrypts it in memory and allows you to view all or 
# parts of it on the command line.  Unless you choose the "dump to plaintext
# file" functionality, this program will never write your safe data to disk,
# thus avoiding the complexity of trying to truly erase private data from
# modern journaling file systems.
# 
# I have developed and tested this on Linux (Xubuntu 11.10) with Ruby 1.9.2
# 
# It has a more explicit data format than the more cryptic pwsafe.rb
# that I wrote first.  pwsafe.rb just takes a triplet of info separated
# by colons.  This one has 6 explicit fields:
#  Name - name of the entity you are storing the password for
#  Key - a shorthand key to look it up (optional - defaults to Name)
#  Username - required
#  Password - required
#  URL - optional
#  Notes - any text, but must fit on one line
# 
# By default this one stores the encrypted password safe at $HOME/.pwsafe
# where as pwsafe.rb stores it as $HOME/.pws
# 
# I recommend running this with rlwrap:
# rlwrap pwsafe2.rb, as it gives you up/down arrow history - makes life nice :)
# 
# Another advantage of pwsafe2 over pwsafe is that it uses GPG libraries to do
# the encryption, so you can use the command line gpg program to unencrypt the
# .pwsafe file, in case this program is ever lost or stops working.
# 
# TODO: 
# 1. Write importer of data from .pws format?
# 2. Use AES256, rather than default CAST5
# X. Handle bad password to safe
# X. URLs with ':' are disappearing
# 5. Test using alternate file with -f switch => what file does it write to?
# 
# Author: Michael Peterson
# @midpeter444
# https://github.com/midpeter444

require 'rubygems'
require 'stringio'
require 'gpgme'
require 'fileutils'

DEFAULT_PASSWORD_SAFE_FILE = File.expand_path('~/.pwsafe')
DUMPFILE = "passwordsafe.plain.txt"  # default file for dumping contents to plaintext

# can change at runtime if user uses -f switch on cmd line
@@password_safe_file = DEFAULT_PASSWORD_SAFE_FILE

### -------------------------- ###
### ---[ Class: SafeEntry ]--- ###
### -------------------------- ###

#
# Value object for a password safe entry
# 
class SafeEntry
  #  include Comparable

  attr_accessor :name, :key, :username, :password, :url, :notes

  # Initializes a SafeEntry object
  # 
  # @param [Hash] values
  # @option values [String] :name The name of the WebSite/System - required
  # @option values [String] :key  A shorthand key for the WebSite/System - optional
  # @option values [String] :username - required
  # @option values [String] :password - required
  # @option values [String] :url - optional
  # @option values [String] :notes - optional
  def initialize(values)
    @name     = values[:name] or raise RuntimeError, "no name provided for WebSite: #{values.inspect}"
    @key      = values[:key]
    @key      = @name if @key.nil? || @key == ''
    @username = values[:username]  || ''
    @password = values[:password]  || ''
    @url      = values[:url]       || ''
    @notes    = values[:notes]     || ''
  end
  
  def to_s
    str =    "Name    : " + @name
    str << "\nKey     : " << @key
    str << "\nUsername: " << @username
    str << "\nPassword: " << @password
    str << "\nURL     : " << @url
    str << "\nNotes   : " << @notes
    str
  end
end


### ----------------------------- ###
### ---[ Class: PasswordSafe ]--- ###
### ----------------------------- ###

# Uses the GPGME classes to encryt and decrypt the password safe
# in memory, writing the data back to disk when the write_safe
# method is called.
class PasswordSafe

  attr_accessor :password

  def initialize
    @ary_entries = nil
  end

  def open( password, filename = File.expand_path(@@password_safe_file) )
    @password = password # password for the safe
    @pwsafe   = filename # path to the safe
    @ary_entries = []    # in memory version of entries: ary of SafeEntry_s
    @crypto = GPGME::Crypto.new(:armor => true)
    read_safe
    @ary_entries.sort_by! {|e| e.name }
    self
  end

  # Add a new entry to the password safe
  # 
  # @param [Hash] e with required fields for new entry
  # @option values [String] :name The name of the WebSite - required
  # @option values [String] :key  A shorthand key for the WebSite - optional
  # @option values [String] :username - required
  # @option values [String] :password - required
  # @option values [String] :url - optional
  # @option values [String] :notes - optional
  def add_entry(e)    
    @ary_entries << SafeEntry.new(e)
    self.uniq_and_sort
  end

  def number_of_entries
    @ary_entries.size
  end

  def uniq_and_sort
    @ary_entries.uniq!
    @ary_entries.sort_by! do |e|
      e.name
    end    
  end
  
  # Predicate specifying whether the password safe has been
  # provided a key to be opened.  If not, the open method must
  # be called before you can use the PasswordSafe object
  # 
  # @return [Boolean] true if safe has been provided the correct key to
  #                   to the open the safe and read it into memory 
  def open?
    not @ary_entries.nil?
  end

  # xxxxxxxxxxxxxxxxxx
  # 
  # @param [Number] num size
  # @return [Array<String>] returns xxx
  def update_entry(oldent, newent)
    @ary_entries[ @ary_entries.index(oldent) ] = newent 
    self.uniq_and_sort
  end
  

  # Gets all entries matching or partially matching the key passed in.
  # The key can have "glob" type matching wildcards (e.g., *bank*)
  # which get transformed into regex notation (/.*bank.*/). The match
  # will also ignore case.
  # 
  # @param [String] key - full or partial match to one or more keys
  #   in the password safe
  # @return [Array<SafeEntry>] returns all entries that
  #   that matched the key or Empty List if no match
  def get_entries_by_key(key)
    re = Regexp.new(key.gsub(/\*/, '.*'), true)  # true => ignore case
    @ary_entries.select { |e| re =~ e.key }
  end

  # All SafeEntry objects passed in will be deleted
  # from the safe.
  # 
  # @param [Number] num size
  # @return [Array<String>] returns xxx
  def delete_entries(ary_e)
    # use array difference operator
    @ary_entries = @ary_entries - ary_e
  end

  # For debugging only - call to_s for the format to write to disk
  def inspect
    str = "Safe file: #{@pwsafe}\n"
    str << "Entries: \n"
    str << self.to_s
  end

  # Returns all entries as a string with "--------" line delimeter
  # between them.  The strings are created by calling to_s on each entry.
  # 
  # @param [Array<SafeEntry>] - optional - defaults to the complete list held
  #   in this class, but you can ask it to format a subset by passing that in
  #   as the optional param
  # @return [String] returns String representation of the entries
  def to_s(entries = @ary_entries)
    entries.map { |e| e.to_s }.join( "\n" + ('-' * 50) + "\n")
  end

  # Reads in the contents of the encrypted safe, decrypts it and turns it
  # into in memory data (an array of SafeEntry objects)
  # 
  # @return [void]
  def read_safe
    return if not File.exist? @pwsafe
    cipher = GPGME::Data.new( IO.read(@pwsafe) )
    plaintxt = @crypto.decrypt(cipher, {:password => @password}).read
    
    entry_info = Hash.new

    StringIO.open(plaintxt, "r") do |sio|
      while str = sio.gets
        next if str =~ /^\s*-----/
        matches = str.chomp.match(/^([^:]+):(.*)$/)
        k = matches[1].strip
        v = matches[2].strip

        entry_info[k.downcase.to_sym] = v if v
        if k == "Notes"
          @ary_entries << SafeEntry.new(entry_info)
          entry_info.clear
        end   
      end
    end
  end


  # Encrypts the in memory contents of the safe and writes it to file
  # Currently it encrypts using the default GPG symmetric cipher (CAST5)
  # I want to figure out how to change this later ...
  # 
  # @return [void]
  def write_safe    
    # returns GPGME::Data obj
    cipher = @crypto.encrypt(self.to_s, {
                               :symmetric => true,
                               :password => @password,
                               # :protocol => 4,    #~TODO: need to set algo cipher to AES256 => how???
                               # :file => @pwsafe   #~TODO: this part is not working ...
                             })
    # overwrite safe with write encrypted contents
    File.open(@pwsafe, "wb") do |fw|
      fw.puts cipher.read
    end
    # make backup copy in case something bad happened
    FileUtils.cp(@pwsafe, "#{@pwsafe}.BAK." + Time.now.to_i.to_s)
  end
  
end


### ----------------------------------------- ###
### ---[ START "Main" Procedural Section ]--- ###
### ----------------------------------------- ###


def display_options
  puts "Options available..."
  puts " a:    add entry"
  puts " c:    change safe password"
  puts " del:  delete entry"
  puts " dump: dump all entries to plaintext file"
  puts " g:    get an entry or entries that match a partial string"
  puts " h:    help (show this screen)"
  puts " l:    list all entries"
  puts " q:    quit"
  puts " s:    size (total number entries)"
  puts " u:    update entry"
  print "Enter option: "
end

def valid_options
  "a, c, g, h, l, q, s, u, del or dump"
end

def get_user_choice
  while true
    e = gets
    return e.chomp if e =~ /^[acghlqsu]\s*$/ || e =~ /^del\s*$|^dump\s*$|^quit\s*$/
    puts "Choice not recognized.  Valid options are #{valid_options}"
    print "Enter choice: "
  end
end

def password_prompt(msg = "Enter safe password: ", b_prompt_once = true)
  first = ''
  $stdout.write msg
  $stdout.flush
  begin
    system('stty -echo')
    io = IO.for_fd(0, 'w')  # file desc 0 == STDIN
    first = gets.chomp
    io.puts("")
    io.flush
    
    unless b_prompt_once
      print "Enter password again: "
      second = gets.chomp
      if second != first
        puts "\nSorry passwords do not match. Try again."
        first = password_prompt(msg, b_prompt_once) 
      end
      io.flush
    end

  ensure
    (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
    system('stty echo')
  end

  first
end

def add_new_entry(safe)
  # TODO: need to allow a user to abort or start over ...
  h = prompt_for_all_safe_entry_fields
  safe.add_entry(h)
end

def prompt_for_all_safe_entry_fields
  h = Hash.new
  print "Enter Name: "
  h[:name] = gets.chomp
  print "Key for lookups: "
  h[:key] = gets.chomp
  print "Username: "
  h[:username] = gets.chomp
  print "Password: "
  h[:password] = gets.chomp
  print "URL: "
  h[:url] = gets.chomp
  print "Notes: "
  h[:notes] = gets.chomp
  h
end

def user_lookup_prompt(safe)
  print "Enter lookup key ('*' for wildcards): "
  safe.get_entries_by_key(gets.chomp)
end

def delete_entry(safe)
  ary = user_lookup_prompt(safe)
  if ary.empty?
    puts "No match found"
  else
    puts "This will delete the following entries: "
    ary.each { |e| puts "  #{e.name}" }
    while true
      print "Proceed? (Y/n): "
      sel = gets.chomp
      case sel
      when '', 'y', 'Y'; return safe.delete_entries(ary)
      when 'n', 'N'    ; return 
      end
    end  
  end
end

# Handles interaction with user to get the new
# fields to change in an existing entry.
# 
# @param [PasswordSafe] already opened of course
# @param [SafeEntry] to be updated
# @return [void]
def handle_single_entry_update(safe, entry)
  puts "Matched:\n#{entry.to_s}"
  while true
    print "Edit password (p) or all fields (a)? (P/a): "
    sel = gets.chomp
    case sel
    when '', 'p', 'P'
      sel = :password
      break
    when 'a', 'A'
      sel = :all
      break
    else
      puts "Input '#{sel}' not recognized."
    end
  end  
  
  if sel == :password
    replace = entry.dup
    print "Enter new password: " 
    replace.password = gets.chomp
  else
    h = prompt_for_all_safe_entry_fields
    replace = SafeEntry.new(h)
  end
  safe.update_entry(entry, replace)
end


def update_entry(safe)
  ary = user_lookup_prompt(safe)
  if ary.size == 0
    puts "No entry found"
  elsif ary.size > 1
    puts "*** ERROR: More than one entry matched: ***"
    ary.each {|e| puts "#{e}"}
    puts "Please refine search"
  else
    # size == 1, proceed to get new info
    handle_single_entry_update(safe, ary.first)
  end
end

def get_entry(safe)
  r = safe.to_s( user_lookup_prompt(safe) )
  puts r != '' ? r : "No match found"
end

def list_all_entries(safe)
  puts safe.to_s
end

def change_safe_password(safe)
  safe.password = password_prompt("Enter new safe password: ", false)
end

def dump_to_file(safe)
  File.open(DUMPFILE, "w") do |fw|
    fw.puts safe.to_s
  end
  puts "Plain text password safe written to file: #{DUMPFILE}"
end

def print_size(safe)
  puts "Number of entries in the safe: #{safe.number_of_entries}"
end

def handle_request(entry, safe)
  open_safe(safe) if not safe.open?
  case entry
  when 'a'    then add_new_entry(safe)
  when 'del'  then delete_entry(safe)
  when 'u'    then update_entry(safe)
  when 'dump' then dump_to_file(safe)
  when 'g'    then get_entry(safe)
  when 'l'    then list_all_entries(safe)
  when 'c'    then change_safe_password(safe)
  when 's'    then print_size(safe)
  else raise RuntimeError, "Unknown user entry '#{entry}'"
  end
end

def open_safe(safe)
  password = ''
  if not File.exist? @@password_safe_file
    puts "Password safe file does not exist."
    password = password_prompt("Enter password to create new safe: ", false)
  else
    password = password_prompt
  end
  begin
    safe.open(password)
  rescue => ex
    case ex
    when GPGME::Error::DecryptFailed
      puts "ERROR: Incorrect password"
      open_safe(safe)
    else
      raise ex
    end
  end
end

def close_safe(safe)
  safe.write_safe if safe.open?
end

def help_and_exit
  $stderr.puts "pwsafe2.rb [OPTIONS]"
  $stderr.puts "  -h      : this help screen"
  $stderr.puts "  -f FILE : use alternative encrypted pwsafe password file"
  exit
end

def main
  if ARGV.size > 0
    if ARGV.first =~ /-{1,2}h(elp)?/
      help_and_exit
    elsif ARGV.first == '-f' && ARGV.size == 2
      if File.exist? ARGV[1]
        @@password_safe_file = ARGV[1]
      else
        $stderr.puts "ERROR: file '#{ARGV[1]}' cannot be found"
        exit
      end
    else
      $stderr.puts "ERROR: command line switch not recognized"
      help_and_exit
    end
  end

  puts "=== Welcome to Password Safe ==="

  # initialize an unopened safe
  # don't prompt for password until they choose an action that requires it
  safe = PasswordSafe.new
  display_options

  # loop until user explicit says to quit (with 'q')
  while true
    e = get_user_choice
    break if e =~ /^q/
    if e =~ /^h/
      display_options
    else
      handle_request(e, safe)
      print "Enter choice (#{valid_options}): "
    end
  end  
  close_safe(safe)

rescue => ex
  $stderr.puts "Error: #{ex}"
  ex.backtrace
  exit(-1)
end


if __FILE__ == $0
  main
end
