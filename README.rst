tetrars
=======

*Replace the Cilium tetra client combined with an ugly grep with a
process that does better filtering.*

In this case, we're interested in getting info by all ``execve()`` calls
by non-system users; that is users with audit ID (auid) 1000 or greater.


----------------
Before-situation
----------------

A way to get *json* logs of ``execve()`` calls is to ask the Cilium
tetragon daemon and then keeping only the lines where
``"auid":<number>`` is high enough.

For example:

.. code-block:: shell

    #!/bin/sh
    fields="process.pid,process.uid,process.auid,process.cwd,process.binary,\
    process.arguments,process.process_credentials,process.binary_properties,\
    parent.pid,parent.binary,parent.cwd"

    /usr/local/bin/tetra \
            --server-address 'unix:///var/run/tetragon/tetragon.sock' \
            getevents -e PROCESS_EXEC -f "$fields" |
        grep --line-buffered '"auid":[0-9]\{4\}[,}]'

You can just feed this to your local log daemon and be done. The lines
might look like this (indented for clarity):

.. code-block:: json

    {
      "process_exec": {
        "process": {
          "pid": 1622809,
          "uid": 0,
          "cwd": "/",
          "binary": "/usr/bin/uname",
          "arguments": "-o",
          "auid": 1000,
          "process_credentials": {
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "suid": 0, "sgid": 0
            "fsuid": 0, "fsgid": 0
          }
        },
        "parent": {
          "pid": 1622808,
          "cwd": "/",
          "binary": "/etc/update-motd.d/00-header"
        }
      },
      "node_name": "node1.example.com",
      "time": "2025-05-27T18:35:20.030763304Z"
    }


---------------
After-situation
---------------

The *after-situation* has the same output, but now we simply spawn *tetrars*.

+------------------------------------+------------------------------------+
| Disadvantages                      | Advantages                         |
+====================================+====================================+
| Coding this was more work than     | Coding this in rust is a good      |
| creating the grep(1) version.      | excuse to improve gRPC and rust    |
|                                    | skills.                            |
+------------------------------------+------------------------------------+
| Changes to the Cilium tetragon API | This rust version has lower memory |
| require a project rebuild. Using   | (and probably cpu) usage than the  |
| grep works always (until the tetra | tetra client. (Logical because it  |
| client changes the json output).   | only has exactly one task.)        |
+------------------------------------+------------------------------------+
| Changes to the Cilium tetragon     | We can do more complicated/correct |
| gRPC API require a project         | filtering. And alter/extend the    |
| rebuild.                           | json output to our liking.         |
+------------------------------------+------------------------------------+

Non-scientific test::

    $ ps -o lstart,vsz,rss,cputimes,comm -p 653,1669131,1669046
                     STARTED      VSZ    RSS  TIME  COMMAND
    Wed May 14 16:10:24 2025  1428188  64612  2316  tetragon
    Tue May 27 23:05:11 2025  1277632  28316    29  tetra
    Tue May 27 23:05:32 2025   141480   3468     7  tetrars

This shows that the demo version of *tetrars* used 8-9x less memory and
up to 4x less cpu.


-----------------------
Binary version and SBOM
-----------------------

The ``git describe`` version is stored and shown on startup:

.. code-block:: console

    $ ./target/release/tetrars
    tetrars v0.1.2 started
    ...

The built binary (if built using ``cargo auditable build``) includes a
*Software Bill of Materials* (SBOM):

.. code-block:: console

    $ objcopy --dump-section .dep-v0=/dev/stdout target/release/tetrars |
        python3 -c 'import zlib,sys;print(zlib.decompress(sys.stdin.buffer.read()).decode("utf-8"))' |
        jq .
    {
      "packages": [
        {
          "name": "aho-corasick",
          "version": "1.1.3",
          "source": "crates.io",
          "kind": "build",
          "dependencies": [
            44
          ]
        },
    ...
