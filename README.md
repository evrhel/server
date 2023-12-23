# server

This is a simple HTTP and HTTPS server written in C. It
has support for a basic user authentication system and
can serve static files.

It makes use of OpenSSL for HTTPS and the encryption of
user data and SQLite for storing user data.

## Building

To build the server, first run `autoreconf -i` to
generate the configure script, then `./configure` to
generate the Makefile.

The server requires OpenSSL to be installed on the
system. Installing to the default location should work.

Once the Makefile is generated, run `make` to build the
server.

Windows is not supported.

## Running

Use `./server` to run the server. To see all available
options, run `./server --help`.

By default, the server attempts to use HTTPS, but will
use HTTP if it cannot. To force the server to use HTTPS,
use the `--https` option, which will cause the server to
exit if it cannot use HTTPS. To force HTTP, use the
`--http` option.

## Layout

The server uses the following directories by default:

* `store`: Private and sensitive files, such as
    certificates and user data.
* `webroot`: Publicly accessible files.

## User authentication

The server uses a simple user authentication system. By
default, the server will look for a file called
`users.db` in the `store` directory which contains
encrypted user data.

To manage users, use the `./server --user` command, use
`./server --user help` to see the available options.
