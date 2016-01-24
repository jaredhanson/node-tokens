include node_modules/@jaredhanson/make-node/main.mk


SOURCES ?= lib/*.js lib/**/*.js
TESTS ?= test/*.test.js test/**/*.test.js

MOCHAFLAGS = --require ./test/bootstrap/node
LCOVFILE = ./reports/coverage/lcov.info


view-docs:
	open ./docs/index.html

view-cov:
	open ./reports/coverage/lcov-report/index.html

clean: clean-docs clean-cov
	-rm -r $(REPORTSDIR)

clobber: clean
	-rm -r node_modules


.PHONY: clean clobber
