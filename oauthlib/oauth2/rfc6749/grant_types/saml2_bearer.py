# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import json
import logging

from .. import errors
from ..request_validator import RequestValidator
from .base import GrantTypeBase

log = logging.getLogger(__name__)


class SAML2BearerGrant(GrantTypeBase):

    GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:saml2-bearer'

    def create_token_response(self, request, token_handler):
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            if self.request_validator.client_authentication_required(request):
                log.debug('Authenticating client, %r.', request)
                if not self.request_validator.authenticate_client(request):
                    log.debug('Client authentication failed, %r.', request)
                    raise errors.InvalidClientError(request=request)
            elif not self.request_validator.authenticate_client_id(request.client_id, request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError(request=request)
            log.debug('Validating access token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request, %s.', e)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, self.refresh_token, save_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token)
        self.request_validator.save_token(token, request)

        log.debug('Issuing token %r to client id %r (%r) and username %s.',
                  token, request.client_id, request.client, request.username)
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        for validator in self.custom_validators.pre_token:
            validator(request)

        for param in ('grant_type', 'assertion'):
            if not getattr(request, param, None):
                raise errors.InvalidRequestError(
                    'Request is missing %s parameter.' % param, request=request)

        for param in ('grant_type', 'assertion', 'scope'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        # This error should rarely (if ever) occur if requests are routed to
        # grant type handlers based on the grant_type parameter.
        if not request.grant_type == self.GRANT_TYPE:
            raise errors.UnsupportedGrantTypeError(request=request)

        log.debug('Validating SAML 2.0 response %s', request)
        if not self.request_validator.validate_saml2_response(request.assertion,
                                                              request.client, request):
            raise errors.InvalidGrantError(
                'Invalid SAML 2.0 response given.', request=request)
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError(
                    'Validate SAML 2.0 response must set the '
                    'request.client.client_id attribute '
                    'in authenticate_client.')

        if not request.user:
            raise errors.InvalidGrantError('Missing user in SAML2 response', request=request)

        log.debug('Authorizing access to user %r.', request.user)

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        if request.client:
            request.client_id = request.client_id or request.client.client_id
        self.validate_scopes(request)

        for validator in self.custom_validators.post_token:
            validator(request)
