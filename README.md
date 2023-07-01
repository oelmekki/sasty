# Sasty

Sasty is a ncurses interface to read [Gitlab's SAST reports](https://docs.gitlab.com/ee/user/application_security/index.html#view-security-scan-information-in-merge-requests).

![Screenshot](./screenshot.png)

> Note for Github users : development is happening
> on [Gitlab](https://gitlab.com/oelmekki/sasty), please submit any issue
> there or merge request there.

## Dependencies

Sasty depends on:

* **gcc** (gentoo: sys-devel/gcc, debian/ubuntu: gcc)
  * Note that you can use an other compiler with the `CC` variable.
* **make** (gentoo: sys-devel/make, debian/ubuntu: make)
* **pkg-config** (gentoo: dev-util/pkgconf, debian/ubuntu: pkg-config)
* **ncurses** (gentoo: sys-libs/ncurses, debian/ubuntu: libncursesw5-dev)
* **json-c** (gentoo: dev-libs/json-c, debian/ubuntu: libjson-c-dev)

## Installation

```
make                          # build with gcc
# make CC=clang               # build with clang instead
sudo make install             # will install in /usr/local/bin
# make install PREFIX=~/      # will install instead in ~/bin
```

## Usage

```
sasty [-h|--help] <file> 

Brings a ncurses interface to inspect Gitlab's SAST reports. 

You must provide a path to a downloaded JSON report. 
```

## Compatibility?

Note that it's the first time I publish a ncurses program, so I have no
clue if this will be cross-platform. If it doesn't build on your platform,
please let me know in the [issues](https://gitlab.com/oelmekki/sasty/-/issues).
