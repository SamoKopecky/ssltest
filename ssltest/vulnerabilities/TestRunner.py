import concurrent.futures as cf
import importlib.util
import inspect
import logging

from ..sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class TestRunner:
    test_module = importlib.import_module(".tests", __package__)

    def __init__(self, address, protocol, supported_protocols):
        """
        Constructor

        :param SocketAddress address: Webserver address
        :param str protocol: SSL/TLS protocol
        :param list[str] supported_protocols: Webservers supported SSL/TLS protocols
        """
        self.address = address
        self.protocol = protocol
        self.supported_protocols = supported_protocols

    def run_tests(self, test_classes):
        """
        Run chosen vulnerability tests in parallel

        :param list test_classes: List of test numbers
        :return: Tests results
        :rtype: dict
        """
        classes_len = len(test_classes)
        if classes_len == 0:
            return {}
        # Output dictionary
        output = {}
        # Dictionary that all the threads live in where the key
        # is the thread (future) and value is the function name
        futures = {}
        log.info(f"Creating {classes_len} threads for vulnerability tests")
        with cf.ThreadPoolExecutor(max_workers=classes_len) as executor:
            for test_class in test_classes:
                scan_class = test_class(
                    self.supported_protocols, self.address, self.protocol
                )
                execution = executor.submit(scan_class.scan)
                futures.update({execution: test_class.name})
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
        tests = {0: None}
        idx = 1
        for name, obj in inspect.getmembers(TestRunner.test_module, inspect.ismodule):
            if not inspect.getdoc(obj).startswith("Vulnerability test for"):
                continue
            test_class = next(m[1] for m in inspect.getmembers(obj) if m[0] == name)
            tests.update({idx: test_class})
            idx += 1
        return tests
