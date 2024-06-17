from concurrent.futures import ThreadPoolExecutor, as_completed, wait
import http.server
import random
import socketserver
import ssl
import time
import unittest

from OpenSSL import crypto


def generate_certificate(subj, key_file, cert_file):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = subj
    cert.set_serial_number(random.randrange(10, 10000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    if subj == "localhost":
        cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost, IP:127.0.0.1")
        ])
    cert.sign(key, 'sha256')
    with open(cert_file, "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        cert = self.connection.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        subject_name = subject.get('commonName', 'Unknown')
        self.wfile.write(f'CN: {subject_name} / URL: {self.path}'.encode())

    def log_message(self, format, *args):
        pass


class HTTPSServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.ssl_context.load_cert_chain("server.crt", "server.key")
        self.ssl_context.set_ciphers("@SECLEVEL=1:ALL")
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.load_verify_locations("client1.crt")
        self.ssl_context.load_verify_locations("client2.crt")
        self.ssl_context.load_verify_locations("client3.crt")
        self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)


# Hack to add self-signed cert to the default context. This needs to happen
# before importing `requests`.
import certifi.core
certifi.core._CACERT_PATH = "server.crt"

import requests

stop_server = None


def run_server():
    global stop_server
    with HTTPSServer(('localhost', 8443), MyHTTPRequestHandler) as httpsd:
        print("Server started on port 8443...")
        stop_server = httpsd.shutdown
        httpsd.serve_forever()


def run_client(name, results):
    session = requests.Session()
    session.cert = (f"{name}.crt", f"{name}.key")
    try:
        print(f"Client {name} making request...")
        resp = session.request("GET", f"https://127.0.0.1:8443/{name}")
        expected = f"CN: {name} / URL: /{name}"
        if resp.text == expected:
            results.append(f"  OK {name}: {resp.text}")
        else:
            results.append(f"FAIL {name}: {resp.text}")
    except Exception as e:
        results.append(f"FAIL {name}: {e}")


class TestHTTPSServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Setting up...")
        generate_certificate("localhost", "server.key", "server.crt")
        generate_certificate("client1", "client1.key", "client1.crt")
        generate_certificate("client2", "client2.key", "client2.crt")
        generate_certificate("client3", "client3.key", "client3.crt")

        cls.executor = ThreadPoolExecutor(max_workers=10)
        cls.server_future = cls.executor.submit(run_server)
        time.sleep(1)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        global stop_server
        if stop_server:
            stop_server()
        cls.executor.shutdown(wait=True)

    def test_clients(self):
        """
        Ref: https://github.com/psf/requests/issues/6726
        """

        results = []
        with ThreadPoolExecutor() as ex:
            futures = [
                ex.submit(run_client, "client1", results),
                ex.submit(run_client, "client2", results),
                ex.submit(run_client, "client3", results)
            ]

            for future in as_completed(futures, timeout=30):  # Timeout after 30 seconds
                try:
                    future.result()
                except Exception as e:
                    results.append(f"Client request failed: {e}")

        for result in results:
            print(result)
            self.assertNotIn("FAIL", result, result)


if __name__ == "__main__":
    unittest.main()
