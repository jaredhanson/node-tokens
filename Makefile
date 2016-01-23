include node_modules/@jaredhanson/make-node/main.mk


SOURCES ?= lib/*.js lib/**/*.js
TESTS ?= test/*.test.js test/**/*.test.js

LCOVFILE = ./reports/coverage/lcov.info

MOCHAFLAGS = --require ./test/bootstrap/node
ISTANBULFLAGS = --dir ./reports/coverage




view-cov:
	open ./reports/coverage/lcov-report/index.html


# ==============================================================================
# Node.js
# ==============================================================================
include support/mk/node.mk



# ==============================================================================
# Clean
# ==============================================================================
clean:
	rm -rf build
	rm -rf reports

clobber: clean clobber-node


.PHONY: view-cov clean clobber
