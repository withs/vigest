rdeb:
	v run .

deb:
	v .

debc:
	v . -o deb.c

prod:
	v -prod -shared .

test:
	v -stats test .

fmt:
	v fmt -w .

doc:
	rm -r docs && v doc -f html -o . -inline-assets -m . && mv _docs docs && mv docs/vigest_auth.html docs/index.html

install:
	rm -r ~/.vmodules/vigest_auth && mkdir ~/.vmodules/vigest_auth && cp -r * ~/.vmodules/vigest_auth
