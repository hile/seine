# vim: noexpandtab, tabstop=4
#

ifndef PREFIX
	PREFIX:=/usr/local
endif
VERSION= $(shell awk -F\' '/^VERSION/ {print $$2}' setup.py)

clean:
	@echo "Cleanup python build directories"
	rm -rf build dist *.egg-info */*.egg-info *.pyc */*.pyc

package: clean
	rm -rf seine-$(VERSION)
	mkdir -p seine-$(VERSION)
	for f in Makefile README.txt bin seine setup.py;do cp -R $$f seine-$(VERSION)/$$d;done
	tar -zcf ../seine-$(VERSION).tar.gz --exclude=.git --exclude=.gitignore --exclude=*.swp --exclude=*.pyc seine-$(VERSION) 

modules:
	python setup.py build

install_modules: modules
	@echo "Installing python modules"
	@python setup.py install

install: install_modules 
	@echo "Installing scripts to $(PREFIX)/bin/"
	@install -m 0755 -d $(PREFIX)/bin
	@for f in bin/*; do \
		echo " $(PREFIX)/$$f";install -m 755 $$f $(PREFIX)/bin/; \
	done;

