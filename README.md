site-builder
============

Builds a Jekyll site, puts it in a gzipped tar archive, and POSTs the archive
to some URL.

I hacked this together to solve the problem of "I want to deploy a Jekyll site
on a shared web hosting service where running Jekyll itself is very difficult /
impossible."

Intended to be run on Heroku - configure and push to Heroku, and everything
should Just Work.

configuration
-------------

* **HOSTNAME**: the server hostname. Used in error messages. Usually
  "something.herokuapp.com".
* **SECURE**: whether to require HTTPS. Defaults to true. Leave this out for
  production deployments; the idea is to set it to false during development.
* **GITHUB_SECRET**: the secret key used for authenticated web hooks. Generate
  a secret key and put it here as well as into the GitHub web hook interface.
* **AUTHORIZED_ACCOUNTS** space-separated list of GitHub accounts whose repos
  should be considered trusted. site-builder will refuse to build any site from
  a repo which is not owned by one of these accounts.
* **WORKING_DIRECTORY** where to write stuff to disk. Set it to `/tmp` on
  Heroku.
* **PUBLISH_URLS** a JSON string containing a mapping of branch names to
  publishing URLs. For example, for a production site at example.com, and a
  staging site at staging.example.com:

      {"master": "https://example.com/cgi-bin/upload-site",
       "staging": "https://staging.example.com/cgi-bin/upload-site"}

* **PUBLISH_SECRET** the secret token used for authenticating the POST request
  on the other end. This will simply be sent in the HTTP headers like this:

      Authorization: token <your secret>

  Your 'upload-site' script should verify this token.
