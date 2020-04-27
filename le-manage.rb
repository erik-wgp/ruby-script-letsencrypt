#!/bin/env ruby

require 'openssl'
require 'acme-client'
require 'awesome_print'
require 'webrick'
require 'yaml'

DEBUG = true

#
#  location /.well-known/acme-challenge {
#    alias /home/letsencrypt/challenges;
#  }
#

def usage(err = 0)
   puts <<-EOF

Usage: [ LE_STAGE=1 ] [ LE_RC=/some/alternate/path ] le-manage.rb <command> [ domain ]

LE_RC default is $HOME/.lemanagerc

commands:
   setup
   key-create
   key-register <email>
   cert-create <tag> <domain>
   cert-update <tag> <domain> <threshold>
   cert-createorupdate <tag> <domain> <threshold>
EOF

   exit err
end

def main

   $config = parse_env
   command = ARGV.shift.chomp

   if command =~ /^cert/
      $config["tag"] = ARGV.shift.chomp

      if command != "cert-create"
         $config["primary_domain"] = ARGV[0]
      end
   end

#   $config.each do |k,v|
#      puts "#{k} => #{v.to_s} => " + get_conf_value(k).to_s
#   end

   case command

   when "setup"
       setup_rc(config_file)

   when "key-create"
      command_key_create

   when "key-register"
      (email = ARGV[0]) || usage(1)
      command_key_register(email.chomp)
   
   when "key-test"
      command_key_test
   
   when "cert-create"
      command_cert_create(ARGV)
   
   when "cert-update"
      command_cert_update

   when "cert-force-update"
      command_cert_update(true)

   when "cert-info"
      command_cert_info
      ARGV.each do |a|
         $config["tag"] = a
         command_cert_info
      end

   else
      err_exit "Unknown command: #{command}"
   end

end


def setup_rc(rcfile)
   File.open(rcfile, "w") do |f|
      f.print get_rc
   end

   puts "Created new config file at " + rcfile
end

def config_file
   ENV["LE_RC"] || ENV["HOME"] + "/.lemanagerc"
end

def parse_env

   config_file_path = config_file

   if ! File.exists?(config_file_path)
      puts "Setting up RC file at #{config_file_path}"
      setup_rc(config_file_path)
      exit if ARGV[0] == "setup"
   end

   $config = (YAML.load(File.open(config_file_path)).to_h)["lemanager"]
   $config["home"] = ENV['HOME']

   command = ARGV[0] ? ARGV[0].chomp : nil
   domain = ARGV[1] ? ARGV[1].chomp : nil

   usage(0) unless command

   if $config["mode"] == "stage"
      $config["key_path"] = $config["stage_key_path"]
   else
      $config["key_path"] = $config["production_key_path"]
   end

   $config
end

def get_conf_value(k, depth = 0)
#   puts (" " * depth ) + "LOOKUP: #{k}"

   if depth > 20
      err_exit "Loop detected in config variable interpolation: #{k}"
   end

   if $config[k].nil?
      err_exit "failed to find config value for '#{k}'"
   end

   v = $config[k].dup

   if v !~ /%[tdsh]/
      return v
   end

   interpolations = {
      "tag" => '%t',
      "primary_domain" => '%d',
      "ssl_root" => '%s',
      "home" => '%h'
   }

   interpolations.each do |interp_key,interp_token|
      next if k == interp_key
      next unless $config[interp_key]

      interp_value = get_conf_value(interp_key, depth + 1)
      v.gsub!(interp_token, interp_value)
   end
   v
end

def get_conf_value_verify(k)
   v = get_conf_value(k)
   if (k =~ /_dir$/) || (k =~ /_root/)
      if ! Dir.exists?(v)
         err_exit "error: directory #{v} doesn't exist"
      end
   elsif (k =~ /_path/)
      if ! File.exists?(v)
         err_exit "error: file #{v} doesn't exist"
      end
   end

   v
end

def write_file(file, data)
   File.open(file, "w") do |f|
      f.print data
   end
end

def err_exit(message)
   STDERR.print message + "\n"
   exit 1
end

def get_le_url
   mode = get_conf_value("mode")

   mode == "production" ? 'https://acme-v02.api.letsencrypt.org/directory' : 'https://acme-staging-v02.api.letsencrypt.org/directory'
end

def get_client
   key_path = get_conf_value_verify("key_path")

   private_key = OpenSSL::PKey::RSA.new(File.read(key_path))

   if File.exists?(key_path + ".kid")
      kid = File.open(key_path + ".kid").read.chomp
   end

   client = Acme::Client.new(private_key: private_key, directory: get_le_url, kid: kid)
end

def get_cert_path(tag, domain)
   return $config["LE_SSL_ROOT"] + "/" + tag + "/" + domains[0] + ".crt"
end

def get_new_cert(domain_private_key, domains)
   challenge_dir   = get_conf_value_verify("challenge_dir")

   client = get_client

   order = client.new_order(identifiers: domains)

   challenges_valid = true
   order.authorizations.each do |auth|
      puts "\tstarting challenge"

      challenge = auth.http
#      DEBUG && puts "Setting up challenge in " + $config["LE_CHALLENGE_DIR"] + "/" + challenge.token
      write_file(challenge_dir + "/" + challenge.token, challenge.file_content)

      challenge.request_validation
      while challenge.status == 'pending'
         puts "\t\twaiting for validation..."
         sleep(2)
         challenge.reload
      end
      puts "\t\tchallenge finished with status #{challenge.status}"

      if challenge.status != "valid"
         challenges_valid = false
         break
      end
   end

   if challenges_valid
      # create a new private key
      puts "\tchallenges validated - creating CSR"
      csr = Acme::Client::CertificateRequest.new(private_key: domain_private_key, subject: { common_name: domains[0] }, names: domains)

      puts "\tfinalizing order"
      order.finalize(csr: csr)
      while order.status == 'processing'
         puts "\tprocessing"
         sleep(1)
         challenge.reload
      end

      puts "\tcert order finished with status #{order.status}"
      return order.certificate
   end

   nil
end

def get_cert_expire_days(cert)
   expires_in = ((cert.not_after - Time.now)/(3600 * 24)).to_i
end

def parse_domains_from_cert(cert)
   crt_domains = cert.to_text.scan(/DNS:(\S+)/).flatten.map { |d| d.sub(/,?$/, "") }
   crt_primary = cert.subject.to_s.scan(/\=(.*)/).flatten.first
   domains = [ crt_primary ] + crt_domains.reject { |a| a == crt_primary }.flatten
end

def command_cert_info
   domain_crt_path = get_conf_value("domain_crt_path")
   cert = OpenSSL::X509::Certificate.new(File.read(domain_crt_path))
   printf("%-20s %-4s days %-20s %-60s\n", get_conf_value("tag"), get_cert_expire_days(cert), cert.not_after, parse_domains_from_cert(cert).join(" "))
end

def command_key_create
   key_path = get_conf_value("key_path")

   if File.exists?(key_path)
      err_exit "not overwriting existing keyfile " + key_path
   end

   puts "Creating new key in #{key_path}"
   private_key = OpenSSL::PKey::RSA.new(4096)
   write_file(key_path, private_key)
end

def command_key_test
   key_path = get_conf_value("key_path")

   if ! File.exists?(key_path)
      err_exit "missing keyfile #{key_path}"
   end

   if ! File.exists?(key_path + ".kid")
      err_exit "missing kid file #{key_path}.kid - not registered?"
   end

   if get_client(key_path)
      puts "#{key_path} looks good"
   end
end

def command_key_register(email)
   key_path = get_conf_value_verify("key_path")

   if File.exists?(key_path + ".kid")
      err_exit "account apparently already registered (" + key_path + ".kid already exists)"
   end

   puts "Registering key #{key_path} with email #{email}"

   client = get_client
   account = client.new_account(contact: "mailto:#{email}", terms_of_service_agreed: true)

   if account
      write_file(key_path + ".kid", account.kid)
   end
end

def command_cert_create(domains)
   tag             = get_conf_value("tag")
   domain_crt_path = get_conf_value("domain_crt_path")
   domain_pvt_path = get_conf_value("domain_pvt_path")
   get_conf_value_verify("key_path")

   puts "Creating new cert for #{tag}, domains [#{domains.join(', ')}], in #{domain_crt_path}"

   if ! Dir.exists?(File.dirname(domain_crt_path))
      puts "\tcreating directory " + File.dirname(domain_crt_path)
      Dir.mkdir(File.dirname(domain_crt_path))
   end

   if ! Dir.exists?(File.dirname(domain_pvt_path))
      puts "\tcreating diretory " + File.dirname(domain_pvt_path)
      Dir.mkdir(File.dirname(domain_pvt_path))
   end

   if Dir.glob( File.dirname(domain_crt_path) + "/*.crt").size != 0
      err_exit "cert(s) already exist in " + File.dirname(domain_crt_path)
   elsif Dir.glob( File.dirname(domain_pvt_path) + "/*.pem").size > 1
      err_exit "multiple keys already exist in " + File.dirname(domain_pem_path)
   end

   if ! File.exists?(domain_pvt_path)
      puts "\tgenerating new private key for #{domain_pvt_path}"
      domain_private_key = OpenSSL::PKey::RSA.new(4096)
      write_file(domain_pvt_path, domain_private_key)
   else
      domain_private_key = OpenSSL::PKey::RSA.new(File.read(domain_pvt_path))
   end

   puts "\trequesting new cert for #{tag} (domains #{domains.join(', ')})"

   new_cert = get_new_cert(domain_private_key, domains)

   if new_cert
      puts "\twriting out cert"
      write_file(domain_crt_path, new_cert)
      return true
   end

   STDERR.print "cert generation failed\n"
   return false
end

def command_cert_update(force = false)
   tag              = get_conf_value("tag")
   domain_crt_path  = get_conf_value_verify("domain_crt_path")
   domain_pvt_path  = get_conf_value_verify("domain_pvt_path")
   expire_threshold = get_conf_value("expire_threshold")
   get_conf_value_verify("key_path")

   puts "Updating cert for #{tag} in #{domain_crt_path}"

   if Dir.glob( File.dirname(domain_crt_path) + "/*.crt").size != 1
      err_exit "multiple cert(s) exist in " + File.dirname(domain_crt_path)
   elsif Dir.glob( File.dirname(domain_pvt_path) + "/*.pem").size != 1
      err_exit "multiple keys already exist in " + File.dirname(domain_pem_path)
   end

   existing_cert = OpenSSL::X509::Certificate.new(File.read(domain_crt_path))
   expires_in = get_cert_expire_days(existing_cert)

   if expires_in > expire_threshold
      if force
         puts "\tforcing update (expires in #{expires_in.to_s} days)"
      else
         puts "\tskipping update (expires in #{expires_in.to_s} days)"
         return true
      end
   end

   puts "\tattempting renewal (expires in #{expires_in.to_s} days)"
   ## retrieve domains from cert
   domains = parse_domains_from_cert(existing_cert)
   domain_private_key = OpenSSL::PKey::RSA.new(File.read(domain_pvt_path))

   puts "\tdomains in cert are " + domains.join(' ')

   new_cert = get_new_cert(domain_private_key, domains)

   if new_cert
      puts "\twriting out cert"
      write_file(domain_crt_path, new_cert)
      return true
   end
end

def get_rc
   rctext = <<-EOF
#
# LE manager config
#
# Interpolated variables:
#
#     %h (from ENV $HOME)
#     %d (primary) domain name (implemented but not used at the moment)
#     %t tag
#     %s SSL ROOT
#
#
# Note - all variables can be overriden with env variables prefixed
#        with "LE_"
#
#        For example ssl_root can be overridden with LE_SSL_ROOT
#

lemanager:
   ssl_root: "%h/ssl"
   challenge_dir: "%h/challenges"
   # renew cert when expires in (days)
   expire_threshold: 35

   production_key_path: "%s/account_key.pem"
   stage_key_path: "%s/account_stage_key.pem"

   # stage or production
   mode: stage

   domain_crt_path: "%s/%t/cert.crt"
   domain_pvt_path: "%s/%t/key.pem"

   ### setting to true disables some sanity checks about whether
   ### other certs/keys should exist in the same location as a current domains
EOF

   rctext
end

main
