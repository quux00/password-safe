#!/usr/bin/env ruby

require 'gpgme'

PASSWORD_SAFE_FILE = File.expand_path('~/.pwsafe2')

class WebSiteEntry

  attr_accessor :name, :key, :username, :password, :url, :notes

  # Initializes a WebSiteInfo object
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
    @key      = values[:key]  or values[:name]  # shorthand key if desired
    @username = values[:username] or raise RuntimeError, "no username provided for WebSite: #{values.inspect}"
    @password = values[:password] or raise RuntimeError, "no password provided for WebSite: #{values.inspect}"
    @url      = values[:url] or ''
    @notes    = values[:notes] or ''
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

  def initialize( password, filename = File.expand_path(PASSWORD_SAFE_FILE) )
    @password = password # password for the safe
    @pwsafe   = filename # path to the safe
    @ary_entries = []    # in memory version of entries: ary of WebSiteEntry_s
    read_safe
  end

  def get_entries_by_key(key)
  end
  
  def read
    return if not File.exist? @pwsafe

    entry_info = Hash.new
    File.open(@pwsafe, "r") do |fh|
      while str = fh.gets
        (key, val) = str.split(/\s*:\s*/)
        entry_info[key] = val
        if key == "Notes"
          ary_entries << WebSiteEntry.new(entry_info)
          entry_info.clear
        end        
      end
    end
  end


  def write
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
    return e if e =~ /^[acghlqu]$/ || e =~ /^del$|^dump$|^quit$/
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

def handle_request(entry)
  #DEBUG
  puts "entry = #{entry}"
  #END DEBUG
end

def open_safe
  safe = ''
  password = ''
  if not File.exist? PASSWORD_SAFE_FILE
    puts "Password safe file does not exist."
    password = password_prompt("Enter password to create new safe (q to quit): ", false)
  end
  safe = PasswordSafe.new(password)
  safe
end

def main
  puts "=== Welcome to Password Safe ==="
  safe = open_safe
  display_options
  while true
    e = get_user_choice
    exit if e =~ /^q/
    if e =~ /^h/
      display_options
    else
      handle_request(e)
      print "Enter choice (a, c, g, h, l, u, del or dump): "
    end
  end  
end


if __FILE__ == $0
  main
end
