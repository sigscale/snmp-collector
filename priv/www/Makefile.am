## Makefile.am
## vim: ts=3
##
## Process this file with automake to produce Makefile.in

www_DATA = yarn.lock

LINKS = index.html polymer.json manifest.json images src

$(abs_builddir)/index.html:
	for i in $(LINKS); do \
		if [ ! -e $(abs_builddir)/$$i ]; then \
			$(LN_S) $(srcdir)/$$i; \
		fi; \
	done

yarn.lock:	package.json $(abs_builddir)/index.html
	yarn install
	yarn run build:static

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(wwwdir)
	cp -R $(abs_builddir)/build/esm-bundled/* $(DESTDIR)$(wwwdir)

clean-local:
	-rm -rf yarn.lock build
	for i in $(LINKS); do \
		if [ -L $$i ]; then \
			rm $$i; \
		fi; \
	done
	
