Welcome to valparse's documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   examples
   documentation

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Overview
--------

By default, Valgrind output is printed to ``stderr``. While readable, Valgrind's
unmodified output is not very easily parsable. However, output can be generated
in the form of XML code and redirected to a ``.xml`` file by running Valgrind with
the following options:

.. code-block:: sh

   valgrind --leak-check=full --xml=yes --xml-file=<xml-file-name> ./<executable> <args>

These XML files can be accurately parsed by ``valparse`` to generate a summary of
the Valgrind run.

Example usage
~~~~~~~~~~~~~

Let’s create a very simple program with ``valparse``:

.. code-block:: py

   import valparse

   xml_file = valparse.Parser('./test.xml')
   if xml_file.hasLeaks() or xml_file.hasErrors():
       print("Leaks or errors found!")

Take a look at the programs on the examples page for more examples of API usage.
