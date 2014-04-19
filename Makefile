# vim: noexpandtab  tabstop=4
#
# Install the scrips, configs and python modules
#

PACKAGE := $(shell basename ${PWD})
VERSION := $(shell awk -F\' '/^VERSION/ {print $$2}' setup.py)
SYSTEM := $(shell uname -s)

all: build

clean:
	@rm -rf build
	@rm -rf dist
	@find . -name '*.egg-info'|xargs rm -rf
	[ "$(SYSTEM)" != "FreeBSD" ] && $(MAKE) -C pacparser/src clean || true

build:
	python setup.py build
	git submodule update pacparser
	[ "$(SYSTEM)" != "FreeBSD" ] && $(MAKE) -C pacparser/src pymod || true

ifdef PREFIX
install_modules: build
	python setup.py --no-user-cfg install --prefix=${PREFIX}
	[ "$(SYSTEM)" != "FreeBSD" ] &&  $(MAKE) -C pacparser/src install-pymod EXTRA_ARGS="--prefix=$(PREFIX)" && true
install: install_modules 
	install -m 0755 -d $(PREFIX)/bin
	for f in bin/*; do echo " $(PREFIX)/$$f";install -m 755 $$f $(PREFIX)/bin/;done;
else
install_modules: build 
	python setup.py install
	[ "$(SYSTEM)" != "FreeBSD" ] && $(MAKE) -C pacparser/src install-pymod || true
install: install_modules 
endif

package: clean
	mkdir -p ../packages/$(PACKAGE)
	git log --pretty=format:'%ai %an%n%n%B' > CHANGELOG.txt
	rsync -a . --exclude='*.swp' --exclude=.git --exclude=.gitignore ./ $(PACKAGE)-$(VERSION)/
	rm CHANGELOG.txt
	tar -zcf ../packages/$(PACKAGE)/$(PACKAGE)-$(VERSION).tar.gz --exclude=.git --exclude=.gitignore --exclude=*.swp --exclude=*.pyc $(PACKAGE)-$(VERSION) 
	rm -rf $(PACKAGE)-$(VERSION)

register:
	python setup.py register

