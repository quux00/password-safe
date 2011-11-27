# Password Safe Command Line Programs

I have written a couple of simple "password safe" programs for my own use.  They are published here so others can review or use them if they are interested in how I did it.

I did this in part because I wanted to learn how to use some encryption libraries (in Ruby in this case) and in part because I have a hard time trusting third party password managers, but since there are some good open source ones that's just being paranoid.

## Overview

### pwsafe.rb

The first one *pwsafe.rb* uses the openssl Ruby libraries.  I fashioned it after a version I found on the web by Jan Lelis.  See the top of file rdoc for details and links to his original version.

pwsafe.rb has a very limited data structure: three items separated by a colon.  It uses the AES256 cbc (cipher block chaining) symmetric encryption algorithm.  I created my own way to generate and store a random initialization vector.  I have no idea how (in)secure this usage of an IV is.

I used pwsafe.rb for about a year, so it is reasonably stable and has a few nice features, but is mostly just a self-tailored home spun program for my tastes.  You may not like it.  It stores the encrypted file in ~/.pws by default.

I most typically run it on Ubuntu/Xubuntu/Lubuntu (10.10, 11.04 and 11.10), but I also used it on my Windows Vista machine, where it worked for a while and then became read-only when I upgraded at some point (I think to Ruby 1.9.2).

To use pwsafe.rb you shouldn't need to install anything beyond Ruby 1.9, since the openssl library comes with it.

### pwsafe2.rb

When I learned about the GPGME libraries and the Ruby library for it, I decided to switch to this.  The main reasons are that I know the encryption is secure (see the note about not really being sure how to handle the IV for the openssl library) and that I can always use the gpg command line program directly to decrypt the .pwsafe file, rather than use my program (say in case it breaks on an upgrade to a new version of ruby, or if I can't use it on Windows, for example).

The pwsafe2.rb data structure is more rich - it explicitly allows Name, Key (shorthand lookup), Username, Password, URL and general Notes.

So far I have tested pwsafe2.rb only on Xubuntu 11.10 with Ruby 1.9.2 and on Lubuntu 11.10 with Ruby 1.9.1.

The Ruby GPGME examples for symmetric encryption I have seen only use the default GPG encryption algorithm, which is CAST5.  I prefer to use AES256, but I haven't been able to figure out how to ask for that from GPGME.  That will be an enhancement to pursue.

To use pwsafe2.rb, you will need to install the gpgme ruby gem. I have developed and tested against the 2.0.0 gem.  You will also need the GnuPG program installed and any appropriate libraries that come with it.

## Future Directions

Right now *pwsafe2.rb* code depends on doing a `system("stty -echo")`, which I've discovered is incompatible with JRuby, so you can only run with MRI Ruby.  I plan on testing it on Windows in cygwin or Mingw32 soon.

It could be possible to use the ffi-ncurses ruby gem, but I can't get that to run on my Xubuntu 11.10 machine (can't find the ncurses library), so that's on hold for now as well.

Longer term idea would be to turn this into a GUI (non-command line) based app.  I would probably do it in JRuby using Swing or SWT, as I'd like to relearn how to use those libraries and playing with JRuby is fun.  But low priority for now ...


## General Disclaimer and "License"

These programs are free to anyone else to use or improve upon.  I issue it under the MIT License, copyright 2011: http://www.opensource.org/licenses/mit-license.php.  Note also that pwsafe is based on code from Jan Lelis - see the rdoc header for his license release information.

This is provided with absolutely no warranty.  I am not an expert in crytography, just a general programmer writing things for my own use, so feel free to use, but at your own risk.

-Michael Peterson

Nov 2011

