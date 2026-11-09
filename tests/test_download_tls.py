"""Downloads keep the caller's TLS policy when certificate validation fails."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from automation.utils import download_file


class DownloadTLSTest(unittest.TestCase):
    def test_certificate_failure_does_not_retry_or_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'artifact'
            target.write_bytes(b'existing')
            with patch.dict(os.environ, {}, clear=True), patch(
                'requests.get', side_effect=requests.exceptions.SSLError('invalid certificate')
            ) as get:
                result = download_file({'url': 'https://example.invalid/artifact',
                                        'filename': 'artifact', 'path': directory})
            self.assertNotEqual(result['return'], 0)
            self.assertIn('invalid certificate', result['error'])
            self.assertEqual(get.call_count, 1)
            self.assertIs(get.call_args.kwargs['verify'], True)
            self.assertEqual(target.read_bytes(), b'existing')

    def test_explicit_policy_and_custom_ca_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / 'ca.pem'
            ca.write_text('offline CA fixture')
            policies = [({}, {}, True), ({'verify_ssl': False}, {}, False),
                        ({}, {'MLC_VERIFY_SSL': 'no'}, False),
                        ({}, {'MLC_SSL_CA_FILE': str(ca)}, str(ca))]
            for options, env, expected in policies:
                with self.subTest(options=options, env=env):
                    response = Mock(headers={'Content-Length': '2'}, url='https://example.invalid/a')
                    response.iter_content.return_value = [b'ok']
                    with patch.dict(os.environ, env, clear=True), patch(
                        'requests.get', return_value=response
                    ) as get:
                        result = download_file({'url': response.url, 'filename': 'artifact',
                                                'path': directory, **options})
                    self.assertEqual(result['return'], 0)
                    self.assertEqual(get.call_args.kwargs['verify'], expected)
                    self.assertEqual((Path(directory) / 'artifact').read_bytes(), b'ok')


if __name__ == '__main__':
    unittest.main()
