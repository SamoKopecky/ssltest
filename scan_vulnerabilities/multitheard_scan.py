import concurrent.futures as cf


def scan_vulnerabilities(tests: list, address: tuple):
    """
    Run the tests in tests list in parallel
    :param tests: tests to be run
    :param address: tuple of an url and port
    :return: scanned results
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
            futures.update({executor.submit(test[0], address): test[1]})
        for future in cf.as_completed(futures):
            test_name = futures[future]
            data = future.result()
            output.update({test_name: data})
    return output
