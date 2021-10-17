import concurrent.futures as cf
import importlib
import inspect
import logging

log = logging.getLogger(__name__)


class TestRunner:
    test_module = importlib.import_module(".tests", __package__)

    def __init__(self, address, timeout, protocol, supported_protocols):
        self.address = address
        self.timeout = timeout
        self.protocol = protocol
        self.supported_protocols = supported_protocols

    def run_tests(self, tests):
        """
        Run chosen vulnerability tests in parallel

        :return: Tests results
        :rtype: dict
        """
        classes_len = len(tests)
        if classes_len == 0:
            return {}
        # Output dictionary
        output = {}
        # Dictionary that all the threads live in where the key
        # is the thread (future) and value is the function name
        futures = {}
        log.info(f"Creating {classes_len} threads for vulnerability tests")
        with cf.ThreadPoolExecutor(max_workers=classes_len) as executor:
            for test_class in tests:
                # 0th index is the function, 1st index is the function name
                scan_class = test_class[0](self.supported_protocols, self.address, self.timeout, self.protocol)
                execution = executor.submit(scan_class.scan)
                futures.update({execution: test_class[1]})
            for execution in cf.as_completed(futures):
                function_name = futures[execution]
                data = execution.result()
                output.update({function_name: data})
        return output

    @staticmethod
    def get_tests_switcher():
        """
        Provides all the available tests switcher

        Tests are extracted from the tests package where each class is a test
        :return: All available tests
        :rtype: dict
        """
        switcher = {
            0: (None, 'No test')
        }
        idx = 0
        for name, obj in inspect.getmembers(TestRunner.test_module):
            if not inspect.ismodule(obj):
                continue
            test_class = next(m[1] for m in inspect.getmembers(obj) if m[0] == name)
            switcher.update({idx: (test_class, test_class.test_name)})
            idx += 1
        return switcher
