rdeb:
	v run .

deb:
	v .

debc:
	v . -o deb.c

rprd:
	v -prod run .

prd:
	v -prod .

test:
	v -stats test .

fmt:
	v fmt -w .

doc:
	rm -r docs && v doc -f html -o . -inline-assets -m . && mv _docs docs

install:
	rm -r ~/.vmodules/digest_authentification && mkdir ~/.vmodules/digest_authentification && cp -r * ~/.vmodules/digest_authentification
