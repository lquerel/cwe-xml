# CWE XML

A local in-memory, queryable, and navigable CWE database initialized with one or multiple CWE XML files.
This crate provides a Rust mapping to CWE XML files from the [MITRE](https://cve.mitre.org/) project.

CWE stands for Common Weakness Enumeration.

XML files are available [here](https://cwe.mitre.org/data/downloads.html).

## Features

* Import multiple CWE catalogs (XML format) into a single CWE database.
* Navigate CWE hierarchies and list CWE roots.
* Query the database for weakness by CWE-ID.
* Query the database for categories by CWE-ID.

## Status 

* All CWE files from the Mitre project have been loaded and deserialized with this crate.
* Still very early, no unit tests, no documentation.

## Examples

* [CWE example](/examples/cwe.rs)
