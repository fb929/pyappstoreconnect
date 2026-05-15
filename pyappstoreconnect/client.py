import os
import logging
import inspect
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import json
import datetime
import hashlib
import pickle
import re
import sirp
import base64
import binascii

from .settings import SettingsMixin
from .timeSeriesAnalytics import TimeSeriesAnalyticsMixin
from .appAnalytics import AppAnalyticsMixin
from .benchmarks import BenchmarksMixin
from .metricsWithFilter import MetricsWithFilterMixin
from .metricsWithGroup import MetricsWithGroupMixin
from .acquisition import AcquisitionMixin

class Client(
        SettingsMixin,
        TimeSeriesAnalyticsMixin,
        AppAnalyticsMixin,
        BenchmarksMixin,
        MetricsWithFilterMixin,
        MetricsWithGroupMixin,
        AcquisitionMixin,
    ):
    """
    client for connect to appstoreconnect.apple.com
    based on https://github.com/fastlane/fastlane/blob/master/spaceship/
    usage:
```
import appstoreconnect
client = appstoreconnect.Client()
responses = client.appAnalytics(appleId)
for response in responses:
    print(response)
```
    """

    def __init__(self,
        cacheDirPath="./cache",
        requestsRetry=False,
        requestsRetrySettings={
            "total": 4, # maximum number of retries
            "backoff_factor": 30, # {backoff factor} * (2 ** ({number of previous retries}))
            "status_forcelist": [429, 500, 502, 503, 504], # HTTP status codes to retry on
            "allowed_methods": ['HEAD', 'TRACE', 'GET', 'PUT', 'OPTIONS', 'POST'],
        },
        logLevel=None,
        userAgent=None,
        legacySignin=False,
    ):
        self.logger = logging.getLogger(__name__)
        if logLevel:
            if re.match(r"^(warn|warning)$", logLevel, re.IGNORECASE):
                self.logger.setLevel(logging.WARNING)
            elif re.match(r"^debug$", logLevel, re.IGNORECASE):
                self.logger.setLevel(logging.DEBUG)
            else:
                self.logger.setLevel(logging.INFO)
        args = locals()
        for argName, argValue in args.items():
            if argName != 'self':
                setattr(self, argName, argValue)

        # create cache dir {{
        try:
            os.makedirs(self.cacheDirPath)
        except OSError:
            if not os.path.isdir(self.cacheDirPath):
                raise
        # }}

        # Supported auth types (matches Ruby AUTH_TYPES)
        self.authTypes = ["sa", "hsa", "non-sa", "hsa2"]

        self.xWidgetKey = self.getXWidgetKey()

        # NOTE: hashcash is NOT pre-fetched here anymore.
        # It is fetched fresh on every login() call to avoid stale tokens
        # when the Client object is long-lived (matches Ruby behaviour where
        # fetch_hashcash is called inside perform_login_method / do_sirp).
        self.hashcash = None

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript",
            "X-Requested-With": "XMLHttpRequest",
            "X-Apple-Widget-Key": self.xWidgetKey,
        }
        if userAgent:
            self.headers['User-Agent'] = userAgent

        self.session = requests.Session()
        # requests: define the retry strategy {{
        if self.requestsRetry:
            retryStrategy = Retry(**self.requestsRetrySettings)
            adapter = HTTPAdapter(max_retries=retryStrategy)
            self.session.mount('https://', adapter)
        # }}
        self.session.headers.update(self.headers)

        self.xAppleIdSessionId = None
        self.scnt = None

        # persistent session cookie {{
        self.sessionCacheFile = self.cacheDirPath + '/sessionCacheFile.txt'
        self.getSession()
        # }}

        self.apiSettingsAll = None

    def appleSessionHeaders(self):
        """
        Return additional headers for appleconnect 2FA flow.
        """
        defName = inspect.stack()[0][3]
        headers = {
            'X-Apple-Id-Session-Id': self.xAppleIdSessionId,
            'scnt': self.scnt,
        }
        self.logger.debug(f"def={defName}: headers={headers}")
        return headers

    def getXWidgetKey(self):
        """
        Fetch and cache the x-widget-key (authServiceKey).
        https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/client.rb
        """
        defName = inspect.stack()[0][3]
        cacheFile = self.cacheDirPath + '/WidgetKey.txt'
        if os.path.exists(cacheFile) and os.path.getsize(cacheFile) > 0:
            with open(cacheFile, "r") as f:
                xWidgetKey = f.read().strip()
        else:
            response = requests.get(
                "https://appstoreconnect.apple.com/olympus/v1/app/config",
                params={"hostname": "itunesconnect.apple.com"},
            )
            try:
                data = response.json()
            except Exception as e:
                self.logger.error(f"def={defName}: failed get response.json(), error={str(e)}")
                return None
            xWidgetKey = data['authServiceKey']
            with open(cacheFile, "w") as f:
                f.write(xWidgetKey)

        self.logger.debug(f"def={defName}: xWidgetKey={xWidgetKey}")
        return xWidgetKey

    def getHashcash(self):
        """
        Fetch a fresh hashcash token from Apple's auth endpoint.
        Must be called immediately before a login attempt.
        https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/hashcash.rb
        """
        defName = inspect.stack()[0][3]
        response = requests.get(
            f"https://idmsa.apple.com/appleauth/auth/signin?widgetKey={self.xWidgetKey}"
        )
        headers = response.headers
        bits = headers.get("X-Apple-HC-Bits")
        challenge = headers.get("X-Apple-HC-Challenge")

        if bits is None or challenge is None:
            self.logger.warning(
                f"def={defName}: Unable to find 'X-Apple-HC-Bits' and "
                f"'X-Apple-HC-Challenge', skipping hashcash"
            )
            return None

        # Compute hashcash: find counter so that SHA1(hc) has `bits` leading zero bits
        version = 1
        date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        counter = 0
        bits_int = int(bits)
        while True:
            hc = f"{version}:{bits_int}:{date}:{challenge}::{counter}"
            sha1_hash = hashlib.sha1(hc.encode()).digest()
            binary_hash = bin(int.from_bytes(sha1_hash, byteorder='big'))[2:]
            if binary_hash.zfill(160)[:bits_int] == '0' * bits_int:
                self.logger.debug(f"def={defName}: hc={hc}")
                return hc
            counter += 1

    # ------------------------------------------------------------------
    # Session validation
    # ------------------------------------------------------------------

    def hasValidSession(self):
        """
        Check whether the currently loaded cookies represent a valid session
        by querying the olympus session endpoint.
        Mirrors Ruby's has_valid_session / fetch_olympus_session logic.
        """
        defName = inspect.stack()[0][3]
        try:
            r = self.session.get("https://appstoreconnect.apple.com/olympus/v1/session")
            if r.status_code == 200:
                data = r.json()
                if "provider" in data:
                    self.logger.debug(f"def={defName}: cached session is still valid")
                    return True
        except Exception as e:
            self.logger.debug(f"def={defName}: session check failed: {e}")
        self.logger.debug(f"def={defName}: no valid session found")
        return False

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------

    def getSession(self):
        """Load cookies from disk cache."""
        if os.path.exists(self.sessionCacheFile) and os.path.getsize(self.sessionCacheFile) > 0:
            with open(self.sessionCacheFile, 'rb') as f:
                cookies = pickle.load(f)
                self.session.cookies.update(cookies)

    def storeSession(self):
        """Trust the current 2SV device and persist cookies to disk."""
        headers = self.appleSessionHeaders()
        self.session.get("https://idmsa.apple.com/appleauth/auth/2sv/trust", headers=headers)
        with open(self.sessionCacheFile, 'wb') as f:
            pickle.dump(self.session.cookies, f)

    # ------------------------------------------------------------------
    # Login entry-point
    # ------------------------------------------------------------------

    def login(self, username, password):
        """
        Authenticate with Apple.

        1. Refresh hashcash (must be fresh for every login attempt).
        2. If a valid cached session exists, skip the full login.
        3. Otherwise perform SIRP (default) or legacy sign-in.
        """
        defName = inspect.stack()[0][3]
        self.logger.debug(f"def={defName}: starting")

        # Always fetch a fresh hashcash before attempting login (matches Ruby behaviour)
        self.hashcash = self.getHashcash()
        if self.hashcash:
            self.session.headers.update({"X-Apple-HC": self.hashcash})

        # Short-circuit if the cached session is still alive
        if self.hasValidSession():
            self.logger.debug(f"def={defName}: reusing existing valid session, skipping login")
            self.apiSettingsAll = self.getSettingsAll()
            return True

        if self.legacySignin:
            return self._legacySignin(username, password)
        else:
            return self._sirp(username, password)

    # ------------------------------------------------------------------
    # SIRP authentication
    # ------------------------------------------------------------------

    def _sirp(self, username, password):
        """
        Perform SIRP-based Apple ID login.
        Mirrors Ruby's do_sirp() method, including protocol-aware pbkdf2.
        """
        defName = inspect.stack()[0][3]
        self.logger.debug(f"def={defName}: Starting SIRP Apple ID login")

        client = sirp.Client(2048)
        a = client.start_authentication()

        # --- init request ---
        url = "https://idmsa.apple.com/appleauth/auth/signin/init"
        payload = {
            "a": base64.b64encode(self.to_byte(a)).decode('utf-8'),
            "accountName": username,
            "protocols": ['s2k', 's2k_fo'],
        }
        response = self.session.post(url, json=payload)
        self.logger.debug(
            f"def={defName}: url={url}, response.status_code={response.status_code}"
        )

        try:
            data = response.json()
        except Exception as e:
            self.logger.error(
                f"def={defName}: failed get response.json(), error={str(e)}, "
                f"url='{url}', status='{response.status_code}', text='{response.text}'"
            )
            return None
        self.logger.debug(
            f"def={defName}: Received SIRP signin init response, data='{data}'"
        )

        if "serviceErrors" in data:
            raise Exception(f"def={defName}: serviceErrors in SIRP init response: {data['serviceErrors']}")

        if response.status_code != 200:
            raise Exception(
                f"def={defName}: url={url}, wrong status={response.status_code}, expected 200"
            )

        iteration = data['iteration']
        salt = base64.b64decode(data['salt'])
        b = base64.b64decode(data['b'])
        c = data['c']
        # FIX: read protocol from response and pass to pbkdf2
        # Ruby: protocol = body["protocol"] then pbkdf2(..., protocol)
        protocol = data.get('protocol', 's2k')
        self.logger.debug(
            f"def={defName}: salt='{salt}', b='{b}', c='{c}', protocol='{protocol}'"
        )

        key_length = 32
        encrypted_password = self.pbkdf2(password, salt, iteration, key_length, protocol)
        self.logger.debug(
            f"def={defName}: key_length='{key_length}', encrypted_password='{encrypted_password}'"
        )

        m1 = client.process_challenge(
            username,
            self.to_hex(encrypted_password),
            self.to_hex(salt),
            self.to_hex(b),
            is_password_encrypted=True,
        )
        m2 = client.H_AMK

        if m1 is False:
            raise Exception(f"def={defName}: Error processing SIRP challenge")

        # --- complete request ---
        url = "https://idmsa.apple.com/appleauth/auth/signin/complete"
        payload = {
            'accountName': username,
            'c': c,
            'm1': base64.b64encode(self.to_byte(m1)).strip().decode('utf-8'),
            'm2': base64.b64encode(self.to_byte(m2)).strip().decode('utf-8'),
            'rememberMe': False,
        }
        response = self.session.post(
            url, json=payload, params={'isRememberMeEnabled': False}
        )
        self.logger.debug(
            f"def={defName}: Completed SIRP authentication, "
            f"url='{url}', status={response.status_code}"
        )

        try:
            data = response.json()
        except Exception as e:
            self.logger.error(
                f"def={defName}: failed get response.json(), error={str(e)}, "
                f"url='{url}', status='{response.status_code}', text='{response.text}'"
            )
            return None
        self.logger.debug(f"def={defName}: data='{data}'")

        return self._handleLoginResponse(response, data, defName)

    # ------------------------------------------------------------------
    # Legacy (pre-SIRP) authentication
    # ------------------------------------------------------------------

    def _legacySignin(self, username, password):
        """
        Perform the older direct-password Apple ID login.
        Set legacySignin=True (or env FASTLANE_USE_LEGACY_PRE_SIRP_AUTH) to use.
        """
        defName = inspect.stack()[0][3]
        self.logger.debug(f"def={defName}: Starting legacy Apple ID login")

        url = "https://idmsa.apple.com/appleauth/auth/signin"
        payload = {
            "accountName": username,
            "password": password,
            "rememberMe": True,
        }
        response = self.session.post(url, json=payload)
        self.logger.debug(
            f"def={defName}: url={url}, response.status_code={response.status_code}"
        )

        try:
            data = response.json()
        except Exception as e:
            self.logger.error(
                f"def={defName}: failed get response.json(), error={str(e)}, "
                f"url='{url}', status='{response.status_code}', text='{response.text}'"
            )
            return None

        return self._handleLoginResponse(response, data, defName)

    # ------------------------------------------------------------------
    # Shared login response handler
    # ------------------------------------------------------------------

    def _handleLoginResponse(self, response, data, defName):
        """
        Handle the HTTP response from either SIRP-complete or legacy signin.
        Mirrors Ruby's send_shared_login_request response switch.
        """
        status = response.status_code

        if status == 200:
            self.logger.debug(f"def={defName}: login successful")
            self.apiSettingsAll = self.getSettingsAll()
            return response

        elif status == 409:
            # 2-step / 2-factor required
            self.logger.debug(
                f"def={defName}: status={status}, proceeding to 2FA auth"
            )
            self.handleTwoStepOrFactor(response)
            self.apiSettingsAll = self.getSettingsAll()
            return True

        elif status == 403:
            message = (
                f"url={response.url}, status={status}: "
                "Invalid username and password combination."
            )
            self.logger.error(f"def={defName}: {message}")
            raise Exception(message)

        elif status == 401:
            message = (
                f"url={response.url}, status={status}: "
                "Incorrect login or password."
            )
            self.logger.error(f"def={defName}: {message}")
            raise Exception(message)

        elif status == 412:
            # FIX: Apple ID & Privacy acknowledgement required
            # Ruby: response.status == 412 && AUTH_TYPES.include?(response.body["authType"])
            auth_type = data.get("authType", "")
            if auth_type in self.authTypes:
                message = (
                    "Need to acknowledge Apple's Apple ID and Privacy statement. "
                    "Please manually log into https://appleid.apple.com "
                    "(or https://appstoreconnect.apple.com) to acknowledge the statement. "
                    "Your account might also be asked to upgrade to 2FA."
                )
                self.logger.error(f"def={defName}: {message}")
                raise Exception(message)
            else:
                message = (
                    f"url={response.url}, unexpected status={status}, "
                    f"authType='{auth_type}', body={data}"
                )
                self.logger.error(f"def={defName}: {message}")
                raise Exception(message)

        else:
            message = (
                f"url={response.url}, unexpected status={status}, "
                f"expected 200 or 409; body={data}"
            )
            self.logger.error(f"def={defName}: {message}")
            raise Exception(message)

    # ------------------------------------------------------------------
    # Two-step / Two-factor handling
    # ------------------------------------------------------------------

    def handleTwoStepOrFactor(self, response):
        defName = inspect.stack()[0][3]

        responseHeaders = response.headers
        self.xAppleIdSessionId = responseHeaders["x-apple-id-session-id"]
        self.scnt = responseHeaders["scnt"]

        headers = self.appleSessionHeaders()
        r = self.session.get("https://idmsa.apple.com/appleauth/auth", headers=headers)
        self.logger.debug(f"def={defName}: response.status_code={r.status_code}")

        # 201 = one trusted phone, code sent automatically
        # 202 = multiple trusted phones, user must choose one
        # 423 = warning: too many verification codes have been sent
        if r.status_code in (201, 202, 423):
            try:
                data = r.json()
            except Exception as e:
                raise Exception(
                    f"def={defName}: failed get response.json(), error={str(e)}"
                )
            self.logger.debug(f"def={defName}: response.json()={json.dumps(data)}")

            if 'trustedDevices' in data:
                self.logger.debug(f"def={defName}: trustedDevices={data['trustedDevices']}")
                self.handleTwoStep(r)
            elif 'trustedPhoneNumbers' in data:
                self.logger.debug(
                    f"def={defName}: trustedPhoneNumbers={data['trustedPhoneNumbers']}"
                )
                self.handleTwoFactor(r)
            else:
                raise Exception(
                    f"def={defName}: Two-step/factor indicated but response unrecognised: "
                    f"{r.text}"
                )
        else:
            raise Exception(
                f"def={defName}: bad response.status_code='{r.status_code}', "
                f"text='{r.text}'"
            )

    def handleTwoStep(self, response):
        # TODO: implement code entry for trusted devices
        return

    def handleTwoFactor(self, response):
        defName = inspect.stack()[0][3]
        try:
            data = response.json()
        except Exception as e:
            raise Exception(
                f"def={defName}: failed get response.json(), error={str(e)}"
            )

        securityCode = data["securityCode"]
        codeLength = securityCode["length"]
        trustedPhones = data["trustedPhoneNumbers"]

        # 202: multiple trusted phone numbers — user must choose which one to use
        if response.status_code == 202 or len(trustedPhones) > 1:
            print("Multiple trusted phone numbers available:")
            for i, phone in enumerate(trustedPhones):
                print(f"  [{i}] {phone['numberWithDialCode']}")
            while True:
                try:
                    choice = int(input(f"Select phone number (0-{len(trustedPhones) - 1}): "))
                    if 0 <= choice < len(trustedPhones):
                        break
                    print(f"Please enter a number between 0 and {len(trustedPhones) - 1}")
                except ValueError:
                    print("Invalid input, please enter a number")

            trustedPhone = trustedPhones[choice]

            # For 202 we need to explicitly request the code to be sent to the chosen number
            phoneId = trustedPhone["id"]
            pushMode = trustedPhone['pushMode']
            headers = self.appleSessionHeaders()
            self.logger.debug(
                f"def={defName}: requesting code for phoneId={phoneId}, pushMode={pushMode}"
            )
            r = self.session.put(
                "https://idmsa.apple.com/appleauth/auth/verify/phone",
                json={"phoneNumber": {"id": phoneId}, "mode": pushMode},
                headers=headers,
            )
            self.logger.debug(
                f"def={defName}: code request status={r.status_code}"
            )
        else:
            # 201 / 423: single phone, code was already sent automatically
            trustedPhone = trustedPhones[0]

        phoneNumber = trustedPhone["numberWithDialCode"]
        phoneId = trustedPhone["id"]
        pushMode = trustedPhone['pushMode']
        codeType = 'phone'

        code = input(
            f"Please enter the {codeLength} digit code you received at {phoneNumber}: "
        )
        payload = {
            "securityCode": {"code": str(code)},
            "phoneNumber": {"id": phoneId},
            "mode": pushMode,
        }
        headers = self.appleSessionHeaders()
        r = self.session.post(
            f"https://idmsa.apple.com/appleauth/auth/verify/{codeType}/securitycode",
            json=payload,
            headers=headers,
        )
        self.logger.debug(f"def={defName}: response.status_code={r.status_code}")
        try:
            self.logger.debug(f"def={defName}: response.json()={json.dumps(r.json())}")
        except Exception:
            pass

        if r.status_code == 200:
            self.storeSession()
            return True
        else:
            return False

    # ------------------------------------------------------------------
    # Crypto helpers
    # ------------------------------------------------------------------

    @staticmethod
    def pbkdf2(password, salt, iteration, key_length, protocol='s2k', digest=hashlib.sha256):
        """
        Derive the encrypted password for SIRP.

        FIX: protocol is now respected:
          - 's2k'    → SHA256(password) as raw bytes  (default, current Apple)
          - 's2k_fo' → SHA256(password) as hex string (legacy Apple accounts)
        Mirrors Ruby's pbkdf2() method in client.rb.
        """
        if protocol not in ('s2k', 's2k_fo'):
            raise ValueError(f"Unsupported protocol '{protocol}' for pbkdf2")

        password_bytes = hashlib.sha256(password.encode()).digest()

        if protocol == 's2k_fo':
            # Legacy: use the hex representation of the SHA256 digest as the PBKDF2 password
            password_bytes = binascii.hexlify(password_bytes)

        return hashlib.pbkdf2_hmac(digest().name, password_bytes, salt, iteration, key_length)

    @staticmethod
    def to_hex(s):
        return binascii.hexlify(s).decode()

    @staticmethod
    def to_byte(s):
        return binascii.unhexlify(s)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def timeInterval(self, days):
        currentTime = datetime.datetime.now()
        past = currentTime - datetime.timedelta(days=days)
        startTime = past.strftime("%Y-%m-%dT00:00:00Z")
        endTime = currentTime.strftime("%Y-%m-%dT00:00:00Z")
        return {"startTime": startTime, "endTime": endTime}
