# *valparse,* a parser for Valgrind-generated XML files

[![License](https://img.shields.io/github/license/tzussman/valparse)](https://github.com/tzussman/valparse)
![GitHub issues](https://img.shields.io/github/issues/tzussman/valparse)
[![Build Status](https://github.com/tzussman/valparse/workflows/Build%20Status/badge.svg?branch=main)](https://github.com/tzussman/valparse/actions?query=workflow%3A%22Build+Status%22)
[![codecov](https://codecov.io/gh/tzussman/valparse/branch/main/graph/badge.svg)](https://codecov.io/gh/tzussman/valparse)

*valparse* supports protocol version 4 with [*Memcheck*][memcheck] only, but can be easily modified to support [*Helgrind*][helgrind] and other protocol tools.

[memcheck]: https://valgrind.org/docs/manual/mc-manual.html
[helgrind]: https://valgrind.org/docs/manual/hg-manual.html

## About Valgrind `.xml` files
By default, [Valgrind][valgrind] output is printed to `stderr`. While readable, Valgrind's unmodified output is not very easily parsable. However, output can be generated in the form of XML code and redirected to a `.xml` file by running Valgrind with the following options:

[valgrind]: https://valgrind.org/

```
 valgrind --leak-check=full --xml=yes --xml-file=<xml-file-name> ./<executable> <args>
```
Some examples of `.xml` files generated by Valgrind are included in the `/examples` directory.

Valgrind does not support XML output for fd leaks as of version 3.18.1.

## Features
- Error generation for nonexistent/incorrectly formatted TOPLEVEL tags
- Error generation for nonexistent/incorrectly formatted PROTOCOL tags
- Basic Valgrind output parsing
  - Check for existence of errors or leaks
  - Check for fatal signal
  - Count errors and leaks *(if applicable)*
  - Error and leak parsing *(if applicable)*
  - Fatal signal parsing *(if applicable)*
- Optional user-friendly `.supp` file generation

### TOPLEVEL tags
*valparse* checks for the existence and correct formatting of the following TOPLEVEL tags:
- protocolversion *(4)*
- protocoltool *(memcheck)*

### PROTOCOL tags
*valparse* checks for the existence and correct formatting of the following PROTOCOL tags:
- preamble
- pid
- ppid
- tool
- args
- status
- suppcounts

*Note: Valgrind supplies an 'errorcounts' tag, but it seems largely unreliable. We've decided to generate this information manually.*

### Basic Valgrind output parsing
The primary function of *valparse* is to generate usable content from Valgrind output. *valparse* was created with our grading scripts in mind, so it counts the number of errors, leaks, unique errors, unique leaks, and total bytes leaked. *valparse* also checks for the presence of a fatal signal.

### `.supp` file generation

Within each `<suppression>` tag, Valgrind supplies a `<rawtext>` tag that can be used to make `.supp` files, but it's cryptic and requires direct editing. We've assembled this information manually to make it more user-friendly, customizable, and generally better. *valparse* supports the dynamic generation of `.supp` files, which can be utilised when running Valgrind to suppress certain leaks or errors. Files can be generated in write (default) or append mode, and users can specify suppression names as well as `.supp` file names.

*Written with love by Ivy Basseches, Michael Jan, and Tal Zussman*
