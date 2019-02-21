"""
This is a simple box client for Python 3. Supports:
- Download/upload files
- Search for files/folders
- List folder contents
- Create folders

Supports directly using an access token or a JWT json file. JWT json file
should be stored in the current directory with file name config.json.

1/4/2019, Xianglong Wang
"""

import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import time
import secrets

import jwt

from urllib.request import urlopen
from urllib.request import Request
from urllib.parse import urlencode

import mimetypes
import io
import uuid


class SimpleBoxClient:

    def __init__(self, access_token=None):
        if access_token is None:
            access_token, as_user_id = self._get_box_access_token()
            self.header = self._generate_http_header(access_token, as_user_id)
        else:
            self.header = self._generate_http_header(access_token)

    def _get_box_access_token(self):
        """
        This is an utility function for getting the box access token
        for accessing the comet folder files.

        returns the access token for the box account.
        """
        config = json.load(open('config.json'))
        try:
            as_user_id = config["asUserID"]
        except BaseException:
            as_user_id = None
        app_auth = config["boxAppSettings"]["appAuth"]
        private_key = app_auth["privateKey"]
        passphrase = app_auth["passphrase"]

        # To decrypt the private key we use the cryptography library
        # (https://cryptography.io/en/latest/)
        key = load_pem_private_key(
            data=private_key.encode('utf8'),
            password=passphrase.encode('utf8'),
            backend=default_backend(),
        )

        # We will need the authentication_url  again later,
        # so it is handy to define here
        authentication_url = 'https://api.box.com/oauth2/token'

        claims = {
            'iss': config['boxAppSettings']['clientID'],
            'sub': config['enterpriseID'],
            'box_sub_type': 'enterprise',
            'aud': authentication_url,
            # This is an identifier that helps protect against
            # replay attacks
            'jti': secrets.token_hex(64),
            # We give the assertion a lifetime of 45 seconds
            # before it expires
            'exp': round(time.time()) + 45
        }

        key_id = config['boxAppSettings']['appAuth']['publicKeyID']

        # Rather than constructing the JWT assertion manually, we are
        # using the pyjwt library.
        assertion = jwt.encode(
            claims,
            key,
            # The API support "RS256", "RS384", and "RS512" encryption
            algorithm='RS512',
            headers={
                'kid': key_id
            }
        )

        params = urlencode({
            # This specifies that we are using a JWT assertion
            # to authenticate
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            # Our JWT assertion
            'assertion': assertion,
            # The OAuth 2 client ID and secret
            'client_id': config['boxAppSettings']['clientID'],
            'client_secret': config['boxAppSettings']['clientSecret']
        }).encode()

        # Make the request, parse the JSON,
        # and extract the access token
        if as_user_id is not None:
            request = Request(authentication_url, params,
                              {'As-User': as_user_id})
        else:
            request = Request(authentication_url, params, None)
        response = urlopen(request).read()
        access_token = json.loads(response)['access_token']
        return access_token, as_user_id

    def _generate_http_header(self, access_token, as_user_id=None):
        if as_user_id is not None:
            header = {'Authorization': 'Bearer {0}'.format(access_token),
                      'As-User': as_user_id}
        else:
            header = {'Authorization': 'Bearer {0}'.format(access_token)}
        return header

    def request_folder_and_file_list(self, folder_id=0, limit=50, offset=0):
        # This function takes the access token and returns a JSON list
        # of all the folders and files available in the folder
        request = Request(
            'https://api.box.com/2.0/folders/{0}/items?limit={1}&offset={2}'
            .format(folder_id, limit, offset), None, self.header)
        response = urlopen(request).read()
        response_dict = json.loads(response)
        total_count = response_dict["total_count"]
        folder_and_file_list = response_dict["entries"]
        return total_count, folder_and_file_list

    def search_folder_and_file_with_name(
            self,
            folder_name,
            parent_folder_id=0,
            search_type=None,
            file_extensions=None,
            limit=50,
            offset=0):
        # See if type is correctly set to 'file', 'folder', or 'web_link'.
        # If file_extensions is set, type must be set to 'file'.
        available_types = ['file', 'folder', 'web_link']
        try:
            if search_type is not None and search_type not in available_types:
                raise ValueError(
                    "search_type should be 'file', 'folder', or 'web_link'")
            if file_extensions is not None and (
                    search_type is not 'file' and search_type is not None):
                raise ValueError(
                    "search_type must be 'file' if file_extensions is set")
        except BaseException:
            pass
        # Perform a search query on the parent_folder with the folder_name.
        url = ('https://api.box.com/2.0/search?query={0}'.format(folder_name) +
               '&ancestor_folder_ids={0}'.format(parent_folder_id) +
               '&limit={0}&offset={1}'.format(limit, offset))
        if search_type is not None:
            url += '&type={0}'.format(search_type)
        if file_extensions is not None:
            url += '&file_extensions={0}'.format(file_extensions)
        request = Request(url, None, self.header)
        response = urlopen(request).read()
        response_dict = json.loads(response)
        total_count = response_dict["total_count"]
        folder_and_file_list = response_dict["entries"]
        return total_count, folder_and_file_list

    def download_file_with_id(self, file_id, base_folder='.', verbose=False):
        request = Request(
            'https://api.box.com/2.0/files/{0}'.format(file_id),
            None,
            self.header)
        response = urlopen(request).read()
        response_dict = json.loads(response)
        file_name = response_dict["name"]
        full_path = base_folder + '/' + file_name
        # Request a file with its id
        request = Request(
            'https://api.box.com/2.0/files/{0}/content'.format(file_id),
            None,
            self.header)
        response = urlopen(request).read()
        with open(full_path, 'wb') as f:
            f.write(response)
        if verbose:
            print("{0} downloaded".format(full_path))

    def create_folder(self, folder_name, parent_folder_id):
        parent_folder_id = str(parent_folder_id)
        data = {"name": folder_name, "parent": {"id": parent_folder_id}}
        request = Request('https://api.box.com/2.0/folders', data, self.header)
        response = urlopen(request).read()
        return json.loads(response)

    def upload_file(self, file_name, display_file_name, parent_folder_id):
        boundary_uuid = uuid.uuid4().hex.encode('utf-8')
        # Construct form data for attributes
        parent_folder_id = str(parent_folder_id)
        attributes = {"name": display_file_name,
                      "parent": {"id": parent_folder_id}}
        attributes_str = json.dumps(attributes)
        form_data = ('Content-Disposition: form-data; '
                     'name="attributes"\r\n'.encode('utf-8'))

        # Read file data
        with open(file_name, 'rb') as f:
            f_content = f.read()
            mimetype = mimetypes.guess_type(
                file_name)[0] or 'application/octet-stream'

        # Make a binary buffer and write form data
        buffer = io.BytesIO()
        boundary = b'--' + boundary_uuid + b'\r\n'
        buffer.write(boundary)
        buffer.write(form_data)
        buffer.write(b'\r\n')
        buffer.write(attributes_str.encode('utf-8'))
        buffer.write(b'\r\n')

        # write file data
        buffer.write(boundary)
        buffer.write('Content-Disposition: form-data; name="file"; '
                     'filename={0}\r\n'
                     .format(display_file_name).encode('utf-8'))
        buffer.write('Content-Type: {0}\r\n'.format(mimetype).encode('utf-8'))
        buffer.write(b'\r\n')
        buffer.write(f_content)
        buffer.write(b'\r\n')

        # close out buffer
        buffer.write(b'--' + boundary_uuid + b'--\r\n')

        # create a request
        data = buffer.getvalue()
        header = self.header
        header['Content-Type'] = 'multipart/form-data; boundary={0}'.format(
            boundary_uuid.decode('utf-8'))
        header['Content-Length'] = len(data)
        request = Request(
            "https://upload.box.com/api/2.0/files/content", data, header)
        response = urlopen(request).read()
        return json.loads(response)
