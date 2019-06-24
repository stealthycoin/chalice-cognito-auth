import mock
from io import StringIO

import pytest

from chalice_cognito_auth.decoder import KeyFetcher
from chalice_cognito_auth.decoder import TokenDecoder
from chalice_cognito_auth.exceptions import InvalidToken


# JWT Token
# headers
# {
#   "alg": "RS256",
#   "typ": "JWT",
#   "kid": "key"
# }
# payload
# {
#   "name": "john",
#   "exp": 3600,
#   "aud": "client_id"
# }
JWT_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleSJ9.eyJuYW1lIjoia"
    "m9obiIsImV4cCI6MzYwMCwiYXVkIjoiY2xpZW50X2lkIn0.uuxb4Zlr7wDV7hc6HzP"
    "LLM1ZpWgPBhyJ40YG2PhFyTjOTDrRHZBKU-kWOtVsZRRzKbnJPJEjQ0fwm00uWPWJp"
    "z-KLAQue6Vt65__nith-xkPUdrB8pYgb--h847Yol-ObSnOZMxiaD3P6_k9lMLri9D"
    "3DgVdq3uXorzubG2KurpBKCD0kJQj7P0EpS1x3gYzMaToGVORV2pOFfUiO3Syt3V_a"
    "TrYJjbc_zeB-fsVi7L31jSrDah7rVjhmNAI_-qpOeeZald-cV48tAvXoFFQaY5rovb"
    "a3JlSxKfwb1d0pdjbaFv-HnosU8gOJZieboruf9D332wUoBfL5CP-rZ3Wyg"
)

JWT_N = (
    "33TqqLR3eeUmDtHS89qF3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4"
    "ZdPWbOiMAfDcDzlOxA04DDnEFGAf-kDQiNSe2ZtqC7bnIc8-KSG_qOGQIVaay4Ucr6"
    "ovDkykO5Hxn7OU7sJp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vB"
    "Hk50BMFJbE9iwFwnxCsU5-UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZ"
    "QZlyrFw0buUEf0YN3_Q0auBkdbDR_ES2PbgKTJdkjc_rEeM0TxvOUf7HuUNOhrtAVE"
    "N1D5uuxE1WSw"
)


class TestTokenDecoder:
    def test_can_decode(self):
        mock_fetcher = mock.Mock(spec=KeyFetcher)
        mock_fetcher.get_keys.return_value = [
            {
                "kid": "wrong_key",
            },
            {
                "kid": "key",
                "kty": "RSA",
                "alg": "RS256",
                "n":  JWT_N,
                "e": "AQAB",
            }
        ]
        decoder = TokenDecoder(mock_fetcher, 'client_id', now=lambda: 0)
        claims = decoder.decode(JWT_TOKEN)
        assert claims['name'] == 'john'
        assert claims['aud'] == 'client_id'

    def test_does_raise_error_on_wrong_aud(self):
        mock_fetcher = mock.Mock(spec=KeyFetcher)
        mock_fetcher.get_keys.return_value = [
            {
                "kid": "wrong_key",
            },
            {
                "kid": "key",
                "kty": "RSA",
                "alg": "RS256",
                "n":  JWT_N,
                "e": "AQAB",
            }
        ]
        decoder = TokenDecoder(mock_fetcher, 'wrong_id', now=lambda: 0)
        with pytest.raises(InvalidToken) as e:
            decoder.decode(JWT_TOKEN)
        assert str(e.value) == 'Token was not issued for this audience'

    def test_does_raise_error_on_bad_signature(self):
        mock_fetcher = mock.Mock(spec=KeyFetcher)
        mock_fetcher.get_keys.return_value = [
            {
                "kid": "wrong_key",
            },
            {
                "kid": "key",
                "kty": "RSA",
                "alg": "RS256",
                "n":  JWT_N,
                "e": "AQAB",
            }
        ]
        decoder = TokenDecoder(mock_fetcher, 'client_id', now=lambda: 0)
        with pytest.raises(InvalidToken) as e:
            decoder.decode(JWT_TOKEN[:-2])
        assert str(e.value) == 'Signature verification failed'

    def test_does_raise_error_on_expired_token(self):
        mock_fetcher = mock.Mock(spec=KeyFetcher)
        mock_fetcher.get_keys.return_value = [
            {
                "kid": "wrong_key",
            },
            {
                "kid": "key",
                "kty": "RSA",
                "alg": "RS256",
                "n":  JWT_N,
                "e": "AQAB",
            }
        ]
        decoder = TokenDecoder(mock_fetcher, 'client_id')
        with pytest.raises(InvalidToken) as e:
            decoder.decode(JWT_TOKEN)
        assert str(e.value) == 'Token expired'

    def test_does_raise_error_when_no_key_found(self):
        mock_fetcher = mock.Mock(spec=KeyFetcher)
        mock_fetcher.get_keys.return_value = []
        decoder = TokenDecoder(mock_fetcher, 'client_id')
        with pytest.raises(InvalidToken) as e:
            decoder.decode(JWT_TOKEN)
        assert str(e.value) == 'Could not find kid key'


class TestKeyFetcher:
    def test_can_fetch_keys(self):
        mock_urlopen = mock.Mock()
        mock_urlopen.return_value = StringIO('{"keys": ["keya", "keyb"]}')
        fetcher =  KeyFetcher('mars-west-1', 'id', urlopen=mock_urlopen)

        keys = fetcher.get_keys()

        mock_urlopen.assert_called_with(
            'https://cognito-idp.mars-west-1.amazonaws.com/id/.well-known/'
            'jwks.json'
        )
        assert keys == ['keya', 'keyb']

    def test_does_use_cache_second_call(self):
        mock_urlopen = mock.Mock()
        mock_urlopen.return_value = StringIO('{"keys": ["keya", "keyb"]}')
        fetcher =  KeyFetcher('mars-west-1', 'id', urlopen=mock_urlopen)

        keys_first = fetcher.get_keys()
        keys_second = fetcher.get_keys()

        mock_urlopen.assert_called_once_with(
            'https://cognito-idp.mars-west-1.amazonaws.com/id/.well-known/'
            'jwks.json'
        )
        assert keys_first == ['keya', 'keyb']
        assert keys_second == ['keya', 'keyb']
