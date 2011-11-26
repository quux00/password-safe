#!/usr/bin/env ruby

require 'stringio'
require 'gpgme'

PASSWORD_SAFE_FILE = File.expand_path('~/.pwsafe2')
DUMPFILE = "passwordsafe.plain.txt"  # default file for dumping contents to plaintext


### -------------------------- ###
### ---[ Class: SafeEntry ]--- ###
### -------------------------- ###

# Value object for a password safe entry
# 
# 
# 
class SafeEntry

  attr_accessor :name, :key, :username, :password, :url, :notes

  # Initializes a SafeEntry object
  # 
  # @param [Hash] values
  # @option values [String] :name The name of the WebSite - required
  # @option values [String] :key  A shorthand key for the WebSite - optional
  # @option values [String] :username - required
  # @option values [String] :password - required
  # @option values [String] :url - optional
  # @option values [String] :notes - optional
  def initialize(values)
    @name     = values[:name] or raise RuntimeError, "no name provided for WebSite: #{values.inspect}"
    @key      = values[:key]
    @key      = @name if @key.nil? || @key == ''
    @username = values[:username] or raise RuntimeError, "no username provided for WebSite: #{values.inspect}"
    @password = values[:password] or raise RuntimeError, "no password provided for WebSite: #{values.inspect}"
    @url      = values[:url]      || ''
    @notes    = values[:notes]    || ''

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

class PasswordSafe

  attr_accessor :password

  def initialize
    @ary_entries = nil
  end

  def open( password, filename = File.expand_path(PASSWORD_SAFE_FILE) )
    @password = password # password for the safe
    @pwsafe   = filename # path to the safe
    @ary_entries = []    # in memory version of entries: ary of SafeEntry_s
    @crypto = GPGME::Crypto.new(:armor => true)
    read_safe
    @ary_entries.sort_by! do |e|
      e.name
    end
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
  end

  def sort
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
    self.sort
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

  # For debugging only
  def inspect
    str = "Safe file: #{@pwsafe}\n"
    str << "Entries: \n"
    str << self.to_s
  end

  # Returns all entries as a string with "--------" line delimeter
  # between them.  The strings are created by calling to_s on each entry.
  # 
  # @return [String] returns String representation of all entries in the safe
  def to_s(entries = @ary_entries)
    entries.map { |e| e.to_s }.join( "\n" + ('-' * 50) + "\n")
  end

  # xxxxxxx
  # 
  # 
  # @return [void]
  def read_safe
    return if not File.exist? @pwsafe
    cipher = GPGME::Data.new( IO.read(@pwsafe) )
    plaintxt = @crypto.decrypt(cipher, {:password => @password}).read

    entry_info = Hash.new
    #    File.open(@pwsafe, "r") do |sio|
    StringIO.open(plaintxt, "r") do |sio|
      while str = sio.gets
        (key, val) = str.chomp.split(/\s*:\s*/)
        entry_info[key.downcase.to_sym] = val if val
        if key == "Notes"
          @ary_entries << SafeEntry.new(entry_info)
          entry_info.clear
        end   
      end
    end
  end


  def write_safe    
    # returns GPGME::Data obj
    #~TODO: need to set algo cipher to AES256 => how???
    cipher = @crypto.encrypt(self.to_s, {
                               :symmetric => true,
                               :password => @password,
                               #                               :protocol => 4,
                               #                               :file => @pwsafe        #~TODO: this part is not working ...
                             })
    # overwrite safe with write encrypted contents
    File.open(@pwsafe, "wb") do |fw|
      fw.puts cipher.read
    end
  end
  
end


### ----------------------------------------- ###
### ---[ START "Main" Procedural Section ]--- ###
### ----------------------------------------- ###


def display_options
  puts "Options available..."
  puts " a:    add entry"
  puts " del:  delete entry"
  puts " u:    update entry"
  puts " dump: dump all entries to plaintext file"
  puts " g:    get an entry or entries that match a partial string"
  puts " l:    list all entries"
  puts " c:    change safe password"
  puts " h:    help (show this screen)"
  puts " q:    quit"
  print "Enter option: "
end

def get_user_choice
  while true
    e = gets
    return e.chomp if e =~ /^[acghlqu]$/ || e =~ /^del$|^dump$|^quit$/
    puts "Choice not recognized.  Valid options are a, c, g, h, l, u, del or dump"
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

def update_entry(safe)
  ary = user_lookup_prompt(safe)
  if ary.size == 0
    puts "No entry found"
  elsif ary.size > 1
    puts "More than one entry matched: "
    ary.each {|e| puts "  #{e}"}
    puts "Please refine search"
  else
    # size == 1, proceed to get new info
    puts "Matched:\n#{ary.first.to_s}"
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
      replace = ary.first.dup
      print "Enter new password: " 
      replace.password = gets.chomp
    else
      h = prompt_for_all_safe_entry_fields
      replace = SafeEntry.new(h)
    end
    safe.update_entry(ary.first, replace)
  end
end

def get_entry(safe)
  r = safe.to_s( user_lookup_prompt(safe) )
  puts (r != '' ? r : "No match found")
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

def handle_request(entry, safe)
  safe = open_safe(safe) if not safe.open?
  case entry
  when 'a'    then add_new_entry(safe)
  when 'del'  then delete_entry(safe)
  when 'u'    then update_entry(safe)
  when 'dump' then dump_to_file(safe)
  when 'g'    then get_entry(safe)
  when 'l'    then list_all_entries(safe)
  when 'c'    then change_safe_password(safe)
  else raise RuntimeError, "Unknown user entry '#{entry}'"
  end
  safe
end

def open_safe(safe)
  password = ''
  if not File.exist? PASSWORD_SAFE_FILE
    puts "Password safe file does not exist."
    password = password_prompt("Enter password to create new safe: ", false)
  else
    password = password_prompt
  end
  safe.open(password)
end

def close_safe(safe)
  safe.write_safe if safe.open?
end

def main
  puts "=== Welcome to Password Safe ==="
  safe = PasswordSafe.new
  display_options
  while true
    e = get_user_choice
    break if e =~ /^q/
    if e =~ /^h/
      display_options
    else
      safe = handle_request(e, safe)
      print "Enter choice (a, c, g, h, l, q, u, del or dump): "
    end
  end  
  close_safe(safe)
end


if __FILE__ == $0
  main
end
