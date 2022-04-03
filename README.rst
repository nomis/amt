intel-amt
=========

Forked from `sdague/amt <https://github.com/sdague/amt>`_ with many extra features
added using the `Intel AMT SDK <https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm>`_
and `MeshCommander <https://github.com/Ylianst/MeshCommander>`_.

Use ``--help`` on commands and all sub-commands to find command line arguments.

amthostdb
---------

* Host database

amtctrl
-------

* Boot settings
* KVM configuration
* Power state
* PKI configuration
* Time sync
* TLS configuration
* Upload to web storage
* User configuration
* UUID information
* Version information
* VNC configuration

PKI Certificate Signing Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This needs a "null signed" CSR containing the public key only.
Only OpenSSL 3+ can do this because the signature on the CSR will be invalid.

Convert the AMT raw RSA public key into a generic public key::

    openssl rsa -RSAPublicKey_in -in amt_rsa_public_key.pem -pubout -out amt_public_key.pem

Create a CSR for common name "example.com", signed with a temporary new private key::

    openssl genrsa | openssl x509 -x509toreq -new -subj /CN=example.com -signkey /dev/stdin -force_pubkey amt_public_key.pem -out amt_csr.pem

Provide the CSR to the AMT for it to sign.

Upload MeshCommander to Web Storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To upload the compressed web page, specify the following headers::

    amtctrl ... storage upload -H Content-Encoding gzip -H Content-Type text/html index.htm.gz index.htm

or::

    amtctrl ... storage upload -H Content-Encoding br -H Content-Type text/html index.htm.br index.htm

amtredir
--------

* KVM redirection (VNC protocol)
