# Ruby Letsencrypt Manager

This is a simple script script for managing SSL certs.

## Setup

Running `'le-manage.rb setup'` will create a `.lemanagerc` file:

```
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
```

Changing `mode` will trigger using the stage or production keys as appropriate.

## Nginx Config

Before you can create a cert, you'll need your webserver to respond to the challenge from the letsencrypt servers.

In nginx, this is something like:

```
location /.well-known/acme-challenge {
  alias /home/letsencrypt/challenges;
}
```

You can create a test file (for example, "testme.html", in your challenge folder, and test that it is accessible on the webserver:

     curl http://www.mysite.com/testme.html
     curl http://mysite.com/testme.html

If those commands don't work, you'll need to check your web server logs for the reason.  Note that after too many challenge errors on the production API, you will be temporarily denied access, so manually testing is advised on a new setup.

## Usage

```
./le-manage.rb key-create
./le-manage.rb key-register your@email.address
./le-manage.rb cert-create mysite www.mysite.com mysite.com
```

Then add to your web server something like:

````
  ssl_certificate /home/letsencrypt/ssl/mysite/cert.crt;
  ssl_certificate_key /home/letsencrypt/ssl/mysite/key.pem;
````


## Todo

- Revocation no yet implemented
