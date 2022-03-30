# *valparse,* a parser for Valgrind-generated XML files
*valparse* supports protocol version 4 with [*Memcheck*][memcheck] only, but can be easily modified to support [*Helgrind*][helgrind] and other protocol tools.

[memcheck]: https://valgrind.org/docs/manual/mc-manual.html
[helgrind]: https://valgrind.org/docs/manual/hg-manual.html

## About Valgrind `.xml` files
By default, [Valgrind][valgrind] output is printed to `stderr`.  However, output can be generated in the form of XML code in a `.xml` file by running Valgrind with the following options:

[valgrind]: https://valgrind.org/

```
$ valgrind --leak-check=full --xml=yes --xml-file=<xml-file-name> ./<executable> <args>
```
Some examples of `.xml` files generated by Valgrind are included in the `/examples` directory.

## How to use *valparse*
Haha...

## Features
- Error generation for nonexistent/incorrectly formatted TOPLEVEL tags
- Error generation for nonexistent/incorrectly formatted PROTOCOL tags
- Basic Valgrind output parsing
  - Check for existence of errors or leaks
  - Check for fatal signal
  - Count errors and leaks *(if applicable)*
  - Error and leak parsing *(if applicable)*
  - Fatal signal parsing *(if applicable)*
- Optional `.supp` file generation

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
*valparse* supports the dynamic generation of `.supp` files, which can be utilised when running Valgrind to suppress certain leaks or errors. Files can be generated in write (default) or append mode, and users can specify suppression names as well as `.supp` file names.

*Written with love by Ivy Basseches, Michael Jan, and Tal Zussman*
