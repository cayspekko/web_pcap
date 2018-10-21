import select
import tornado.ioloop
import tornado.web
import subprocess as sub
from threading import Thread
from queue import Queue, Empty
import time
data = {'running': False}
def get_app():
        class ControlHandler(tornado.web.RequestHandler):
            def get(self):
                now = str(time.strftime("%Y%m%d%H%M%S"))
                data = """
<div>
<form method="get" action="../{0}.pcap">
Interface:
<input type="text" name="interface" value="any">
<br>
Args:
<input type="text" name="args" value="">
<br>
Timeout:
<input type="text" name="timeout" value="">
<br><br>
<button type="submit">Start!</button>
</form>
<form method="post" action="../{0}.pcap">
<button type="submit">Stop!</button>
</form>
</div>
"""
                data = data.format(now)
                self.finish(data)
        class FileHandler(tornado.web.RequestHandler):
            def initialize(self, data):
                self.data = data

            def post(self, filename):
                print('-->filename', filename)
                print('-->running', self.data['running'])
                if self.data['running']:
                    self.data['running'].terminate()
                self.redirect('../control')

            @tornado.web.asynchronous
            def get(self, filename):
                print('-->filename', filename)
                if self.data['running']:
                    return

                interface = self.get_argument('interface', 'any')
                args = self.get_argument('args', '')
                
                print('interface', interface, 'args', args)
                
                cmd = ('tcpdump', '-nUi', interface) 
                cmd += (args,) + ('-w','-',)

                print('cmd', cmd)
                self.p = sub.Popen(cmd, stdout=sub.PIPE, stderr=sub.PIPE)
                self.data['running'] = self.p
                self.row = iter(self.p.stdout.readline, b'')
                self.err = iter(self.p.stderr.readline, b'')
                print('-->err:', next(self.err))
                
                self.q = Queue()
                self.t = Thread(target=self.tcpdump_thread, args=(self.p, self.row, self.q))
                self.t.daemon = True
                self.t.start()

                self.timeout = int(self.get_argument('timeout', '') or 0)
                self.start_time = time.time() if self.timeout else 0
                
                self.set_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.write_more()

            def tcpdump_thread(self, p, row, q):
                while p and p.returncode == None:
                    try:
                        for r in row:
                            if r:
                                q.put(r)
                    except SystemError:
                        print('--->System error in thread')
                        pass
                q.join()


            def write_more(self):
                if self.p and self.p.poll() != None:
                    print('-->self.p.poll() returned', self.p.returncode)
                timeout = ((time.time() - self.start_time) < self.timeout) if self.timeout else True
                if self.p and self.p.returncode == None:
                    if not timeout:
                        print('-->timeout out terminating')
                        self.p.terminate()
                        time.sleep(.2)
                    try:
                        while True:
                            data = self.q.get_nowait()
                            self.write(data)
                    except Empty:
                        time.sleep(.2)
                    self.flush(callback=self.write_more)
                else:
                    self.cleanup()
                    self.flush()
                    self.finish()

            def on_connection_close(self):
                print('-->connection closed')
                self.cleanup()

            def cleanup(self):
                if self.p and self.p.returncode == None:
                    print('-->terminate')
                    self.p.terminate()
                    time.sleep(.2)
                queue_lo = 0
                leftovers = 0
                while True:
                    try:
                        data = self.q.get_nowait()
                        self.write(data)
                        queue_lo += 1
                    except Empty:
                        break;
                try:
                    for data in self.row:
                        leftovers += 1
                        self.write(data)
                except SystemError:
                    print('--->system error in cleanup?')
                for err in self.err:
                    print('-->err:', err)

                print('-->leftovers', leftovers, queue_lo)
                self.p = None
                self.data['running'] = None

        return tornado.web.Application([('/(.*).pcap', FileHandler, {"data": data}),
                                        ('/control', ControlHandler)])


if __name__ == "__main__":
    print('-->starting')
    app = get_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
