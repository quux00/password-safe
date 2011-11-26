#!/usr/bin/env ruby

require 'stringio'
require 'gpgme'

PASSWORD_SAFE_FILE = File.expand_path('~/.pwsafe2')
DUMPFILE = "passwordsafe.plain.txt"  # default file for dumping contents to plaintext

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
    #DEBUG
    require 'pp'
    print "DEBUG 11: "
    pp values.to_s
    #END DEBUG
    @name     = values[:name]     or raise RuntimeError, "no name provided for WebSite: #{values.inspect}"
    @key      = values[:key]      || values[:name]  # shorthand key if desired
    #DEBUG
    puts "DEBUG 12: key just set: >>#{@key}<<"
    #END DEBUG
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
  
  # Predicate specifying whether the password safe has been
  # provided a key to be opened.  If not, the open method must
  # be called before you can use the PasswordSafe object
  # 
  # @return [Boolean] true if safe has been provided the correct key to
  #                   to the open the safe and read it into memory 
  def open?
    not @ary_entries.nil?
  end

  def get_entries_by_key(key)
  end

  # For debugging only
  def inspect
    str = "Safe file: #{@pwsafe}\n"
    str << "Entries: \n"
    str << self.to_s
  end

  def to_s
    @ary_entries.map { |e| e.to_s }.join( "\n" + ('-' * 50) + "\n")
  end
  
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
  print msg
  first = gets
  unless b_prompt_once
    print "Enter password again: "
    second = gets
    if second != first
      puts "Sorry passwords do not match. Try again."
      first = password_prompt(msg, b_prompt_once) 
    end
  end
  first
end

def add_new_entry(safe)
  # TODO: need to allow a user to abort or start over ...
  h = Hash.new
  print "Enter Name of new entry: "
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
  safe.add_entry(h)
end

def delete_entry(safe)
end

def update_entry(safe)
end

def get_entry(safe)
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
    password = password_prompt("Enter password to create new safe (q to quit): ", false)
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
