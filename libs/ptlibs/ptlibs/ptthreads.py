import threading
import time

import ptlibs.ptmisclib as ptmisclib

class ptthreads:
    def __init__(self):
        self.threads_list = []
        self.free_threads = []
        self.returns = []
        self.lock = threading.Lock()

    def threads(self, items, function, threads):
        self.free_threads.clear()
        self.threads_list.clear()
        self.returns.clear()
        for i in range(threads):
            self.free_threads.append(i)
            self.threads_list.append("")
        while items:
            if not type(items) == list:
                try:
                    item = next(items).strip()
                except:
                    break
            else:
                item = items[0]
                items.remove(item)
            thread_no = self.free_threads.pop()
            self.threads_list[thread_no] = threading.Thread(
                target = self.wrapper_worker,
                args = (item, function, thread_no),
                daemon=False
            )
            result = self.threads_list[thread_no].start()
            while not self.free_threads:
                time.sleep(0.01)
            while not items:
                time.sleep(0.01)
                if len(self.free_threads) == threads and not items:
                    return self.returns
        for thread in self.threads_list:
            if thread:
                thread.join()

    def wrapper_worker(self, item, function, thread_no):
        self.returns.append(function(item))
        self.free_threads.append(thread_no)


class printlock:
    def __init__(self):
        self.output_string = ""
        self.lock = threading.Lock()

    def add_string_to_output(self, string="", condition=True, end="\n", silent=False, trim=False):
        if condition and not silent:
            if trim:
                string = string.strip()
            if string:
                self.output_string +=  string + end
    
    def get_output_string(self):
        return self.output_string

    def print_output(self, condition=True, end="\n", flush=True):
        if condition and not silent:
            print(self.output_string, end=end, flush=flush)

    def lock_print_output(self, condition=True, end="\n", flush=True):
        if condition:
            self.lock.acquire()
            ptmisclib.ptprint(self.output_string, end=end, flush=flush)
            self.lock.release()
    
    def lock_print(self, string, condition=True, end="\n", flush=True, clear_to_eol=False):
        if condition:
            self.lock.acquire()
            ptmisclib.ptprint(string, end=end, flush=flush, clear_to_eol=clear_to_eol)
            self.lock.release()