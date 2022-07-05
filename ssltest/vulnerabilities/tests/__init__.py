import os
import importlib

# Import these classes to the sys.modules list so that they can be extracted later in TestRunner class
_, _, files = next(os.walk(os.path.dirname(os.path.abspath(__file__))))
not_tests = ["__init__.py"]
files = [file for file in files if file not in not_tests]
[importlib.import_module(__package__ + "." + file[:-3]) for file in files]
