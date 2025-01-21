import unittest
from unittest.mock import patch, MagicMock
from utils.network_scan import NetworkScanner

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner()

    @patch('subprocess.run')
    def test_run_command(self, mock_run):
        mock_run.return_value = MagicMock(stdout='test output')
        result = self.scanner.run_command(['test'])
        self.assertEqual(result, 'test output')

    @patch('socket.gethostbyname')
    def test_scan_network(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.1.1'
        result = self.scanner.scan_network()
        self.assertIsInstance(result, dict)

    def test_scan_ports(self):
        result = self.scanner.scan_ports('localhost', [80, 443])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)

if __name__ == '__main__':
    unittest.main()