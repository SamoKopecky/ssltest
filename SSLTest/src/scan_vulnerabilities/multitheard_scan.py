import concurrent.futures as cf

protocol_binary_version = {
    "TLSv1.3": 0x04,
    "TLSv1.2": 0x03,
    "TLSv1.1": 0x02,
    "TLSv1.0": 0x01,
    "SSLv3": 0x00
}


def scan_vulnerabilities(tests, address, version):
    """
    Run tests in parallel

    :param list tests: Tests to be run
    :param tuple address: Url and port
    :param str version: SSL/TLS version that the server supports
    :return: Tests results
    :rtype: dict
    """
    # Output dictionary
    output = {}
    # Dictionary that all the threads live in where
    # the key is the thread (future) and value is
    # the test name eg. Heartbleed
    futures = {}
    with cf.ThreadPoolExecutor(max_workers=len(tests)) as executor:
        for test in tests:
            # 0th index is the function, 1st index is the test name
            futures.update({executor.submit(test[0], address, protocol_binary_version[version]): test[1]})
        for future in cf.as_completed(futures):
            test_name = futures[future]
            data = future.result()
            output.update({test_name: data})
    return output
