import json
import logging
import os
import subprocess
from typing import Annotated

import mjaf
import requests
from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError
from authlib.jose.errors import DecodeError
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi import Header
from fastapi import HTTPException


mjaf.logging.set_handlers(
    logger_name=__name__,
    level=logging.INFO,
)
log = logging.getLogger(__name__)


load_dotenv()
log.info('Environment loaded')

SECRET_TOKEN = os.getenv('SECRET_TOKEN')


def get_jwt_keys(jwt_server_url):
    request_jwk = requests.get(jwt_server_url)
    request_jwk.raise_for_status()

    jwk = request_jwk.json()
    jwks_keys = jwk['keys']
    return jwks_keys


def call_ducc(image: str | None, cvmfs_repository: str | None):
    string = f'quack: {image}, {cvmfs_repository}'

    log.info(f'{image=}')
    log.info(f'{cvmfs_repository=}')

    stdout = subprocess.run(
        [
            'sudo',
            'systemctl',
            'stop',
            'autofs',
        ],
    )

    # TODO: ensure cvmfs_ducc exists
    subprocess.run(
        [
            'sudo',
            'cvmfs_ducc',
            'convert-single-image',
            image,
            cvmfs_repository,
            '--skip-podman',
            '--skip-thin-image',
        ],
    )


def check_authorization(
    authorization: Annotated[str | None, Header()],
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail='No Authorization header provided',
        )


app = FastAPI()


@app.get('/')
def root():
    return {'message': 'PSI Image Unpacker'}


@app.post('/api/gitlab/sync/jwt')
def gitlab_sync_jwt(
    authorization: Annotated[str | None, Header()] = None,
    image: str | None = None,
    cvmfs_repository: str | None = None,
    gitlab_server: str | None = None,
):
    gitlab_jwks_keys = get_jwt_keys(
        f'https://{gitlab_server}/oauth/discovery/keys',
    )

    check_authorization(authorization)
    try:
        claims = jwt.decode(
            authorization,
            gitlab_jwks_keys,
        )
    except DecodeError:
        raise HTTPException(
            status_code=403,
            detail='Invalid token: DecodeError',
        )
    except BadSignatureError:
        raise HTTPException(
            status_code=403,
            detail='Invalid token: BadSignatureError',
        )
    if claims['iss'] != gitlab_server:
        raise HTTPException(

            detail=f"Invalid issuer {claims['iss']}",
        )

    return call_ducc(image, cvmfs_repository)


@app.post('/api/github/sync/jwt')
def github_sync_jwt(
    authorization: Annotated[str | None, Header()] = None,
    image: str | None = None,
    cvmfs_repository: str | None = None,
):
    github_jwks_keys = get_jwt_keys(
        'https://token.actions.githubusercontent.com/.well-known/jwks',
    )

    check_authorization(authorization)
    try:
        claims = jwt.decode(
            authorization,
            github_jwks_keys,
        )
    except DecodeError:
        raise HTTPException(
            status_code=403,
            detail='Invalid token: DecodeError',
        )
    except BadSignatureError:
        raise HTTPException(
            status_code=403,
            detail='Invalid token: BadSignatureError',
        )
    if claims['iss'] != 'https://token.actions.githubusercontent.com':
        raise HTTPException(
            status_code=403,
            detail=f"Invalid issuer {claims['iss']}",
        )

    return call_ducc(image, cvmfs_repository)


if SECRET_TOKEN is not None:
    @app.post('/api/sync/secret')
    def gitlab_sync_secret(
            authorization: Annotated[str | None, Header()] = None,
            image: str | None = None,
            cvmfs_repository: str | None = None,
    ):

        check_authorization(authorization)

        if authorization != SECRET_TOKEN:
            raise HTTPException(
                status_code=401,
                detail='Invalid authorization token',
            )

        return call_ducc(image, cvmfs_repository)
