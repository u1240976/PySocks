import imp
#for reseting module state

import unittest
import socket
import socks

# week normal test
# [no boundary] socks.HTTP, socks.SOCKS4, socks.SOCKS5
# '0.0.0.0', '127.0.0.1', '255.255.255.255'
# 1, 8000, 65535
# None, 'a', 'hello0925', 'abcdefghijklmnopqrstuvwxyz1234567890'
# None, 'b', 'a5d8om90', '0987654321zyxwvutsrqponmlkjihgfedcba'
class socksocketStaticProxySettingTest(unittest.TestCase):
    """Test proxy setting static method for class attribute.
    """

    def test_set_default_proxy(self):

        socks.set_default_proxy()
        self.assertEqual(socks.socksocket.default_proxy, (None, None, None, True, None, None))

        test_inputs = [
            # normal
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS4, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.HTTP, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            # boundary
            ((socks.SOCKS5, '0.0.0.0', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '255.255.255.255', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 1), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 65535), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': None, 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'a', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'abcdefghijklmnopqrstuvwxyz1234567890', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': None}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'b'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': '0987654321zyxwvutsrqponmlkjihgfedcba'}),
        ]
        test_answers = [
            # normal
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS4, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.HTTP, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            # boundary
            (socks.SOCKS5, '0.0.0.0', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '255.255.255.255', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 1, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 65535, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, None, b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'a', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'abcdefghijklmnopqrstuvwxyz1234567890', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', None),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'b'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'0987654321zyxwvutsrqponmlkjihgfedcba'),
        ]

        for test_input, test_answer in zip(test_inputs, test_answers):
            socks.set_default_proxy(*test_input[0], **test_input[1])
            self.assertEqual(socks.socksocket.default_proxy, test_answer)
            

    def test_get_default_proxy(self):

        socks.socksocket.default_proxy = (None, None, None, True, None, None)
        self.assertEqual(socks.get_default_proxy(), (None, None, None, True, None, None))

        test_inputs_and_answers = [
            # normal
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS4, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.HTTP, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            # boundary
            (socks.SOCKS5, '0.0.0.0', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '255.255.255.255', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 1, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 65535, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, None, b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'a', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'abcdefghijklmnopqrstuvwxyz1234567890', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', None),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'b'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'0987654321zyxwvutsrqponmlkjihgfedcba'),
        ]

        for test_input_and_answer in test_inputs_and_answers:
            socks.socksocket.default_proxy = test_input_and_answer
            self.assertEqual(socks.get_default_proxy(), test_input_and_answer)

# week normal test
# [no boundary] socks.HTTP, socks.SOCKS4, socks.SOCKS5
# '0.0.0.0', '127.0.0.1', '255.255.255.255'
# 1, 8000, 65535
# None, 'a', 'hello0925', 'abcdefghijklmnopqrstuvwxyz1234567890'
# None, 'b', 'a5d8om90', '0987654321zyxwvutsrqponmlkjihgfedcba'
class socksocketProxySettingTestCase(unittest.TestCase):
    """Test proxy setting method for single class instance.
    """

    def setUp(self):
        self.test_socket = socks.socksocket()

    def tearDown(self):
        pass
        
    def test_set_proxy(self):
        self.test_socket.set_proxy()
        self.assertEqual(self.test_socket.proxy, (None, None, None, True, None, None))

        test_inputs = [
            # normal
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS4, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.HTTP, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            # boundary
            ((socks.SOCKS5, '0.0.0.0', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '255.255.255.255', 8000), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 1), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 65535), {'username': 'hello0925', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': None, 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'a', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'abcdefghijklmnopqrstuvwxyz1234567890', 'password': 'a5d8om90'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': None}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': 'b'}),
            ((socks.SOCKS5, '127.0.0.1', 8000), {'username': 'hello0925', 'password': '0987654321zyxwvutsrqponmlkjihgfedcba'}),
        ]
        test_answers = [
            # normal
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS4, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.HTTP, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            # boundary
            (socks.SOCKS5, '0.0.0.0', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '255.255.255.255', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 1, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 65535, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, None, b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'a', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'abcdefghijklmnopqrstuvwxyz1234567890', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', None),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'b'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'0987654321zyxwvutsrqponmlkjihgfedcba'),
        ]

        for test_input, test_answer in zip(test_inputs, test_answers):
            self.test_socket.set_proxy(*test_input[0], **test_input[1])
            self.assertEqual(self.test_socket.proxy, test_answer)

    def test__proxy_addr(self):
        test_inputs = [
            # normal
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS4, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.HTTP, '127.0.0.1', 8000, True, b'hello0925', b'a5d8om90'),
            # boundary
            (socks.SOCKS5, '0.0.0.0', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '255.255.255.255', 8000, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 1, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 65535, True, b'hello0925', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, None, b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'a', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'abcdefghijklmnopqrstuvwxyz1234567890', b'a5d8om90'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', None),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'b'),
            (socks.SOCKS5, '127.0.0.1', 8000, True, b'hello0925', b'0987654321zyxwvutsrqponmlkjihgfedcba'),
        ]

        test_answers = [
            # normal
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            # boundary
            ('0.0.0.0', 8000),
            ('255.255.255.255', 8000),
            ('127.0.0.1', 1),
            ('127.0.0.1', 65535),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
            ('127.0.0.1', 8000),
        ]

        for test_input, test_answer in zip(test_inputs, test_answers):
            self.test_socket.proxy = test_input
            self.assertEqual(self.test_socket._proxy_addr(), test_answer)

class SockSocketCtorTestCase(unittest.TestCase):
    """
    We need to reset the static members in socks module before using it
    """
    def setUp(self):
        imp.reload(socks)

    """
    Normal Test
    """
    def testCtorGerneral_Normal1(self):
        s = socks.socksocket()
        self.assertEqual(s._savenames,[])
        self.assertEqual(s.proxy, (None,None,None,None,None,None))
        for wanted in ("sendto", "send", "recvfrom", "recv"):
             self.assertEqual(True, hasattr(s, wanted))

    def testCtorAF_Normal1(self):
        _testAddrFamily = [socket.AF_INET, socket.AF_INET6]
        for iTestCase in _testAddrFamily:
            s = socks.socksocket(family=iTestCase)
            self.assertEqual(s.family,iTestCase)
    def testCtorSOCK_Normal2(self):
        _testSocketType = [socket.SOCK_STREAM, socket.SOCK_DGRAM]
        with self.assertRaises(ValueError):
            s = socks.socksocket(family=socket.AF_UNIX)
    """
    Robust Test
    """
    def testCtorAF_Robust1(self):
        with self.assertRaises(ValueError):
            s = socks.socksocket(family=socket.AF_UNIX)

if __name__ == '__main__':
    unittest.main(verbosity=2)
