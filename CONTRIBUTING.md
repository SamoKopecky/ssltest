# Contributing

You can contribute by making new vulnerability tests.

## Contribute a new Vulnerability test

5 conditions have to be met for a test to be a valid vulnerability test:

1. The test class has to inherit from the `VulnerablityTest` class and implement required abstract methods and call the
   super constructor (`super().__init__`)
2. The `test` method has to be implemented and has return either a `bool` or a `tuple(bool, str)`
3. The variable `valid_protocols` has to be set to a list of SSL/TLS protocols you want the test to run on
4. Static variables `name`, `short_name` and `description` have to be defined
5. The first line of the file that hosts the test class has to have this format:

```
"""Vulnerability test for {AnyTestName}"""
```

### Other useful tools for implementing tests

- The variable `test_once` can be set to `False` to run the test on multiple protocol versions in parallel. Protocols
  are chosen based on the intersection of `valid_protocols` and `supported_protocols` lits.
- The method `run_once()` can be implemented in case the `test_once` variable is set to `False` to run some code before
  the parallel run of tests on multiple protocols (e.g. `Drown`).
- The `ClientHello` class can be used to create the initial client hello message, where every client hello field can be
  customized such as cipher suites or TLS extensions.
  