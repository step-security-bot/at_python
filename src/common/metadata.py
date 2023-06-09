import json
import datetime
from dateutil.parser import parse
from dataclasses import dataclass


@dataclass
class Metadata:
    ttl: int = 0
    ttb: int = 0
    ttr: int = 0
    ccd: bool = False
    created_by: str = None
    updated_by: str = None
    available_at: datetime.datetime = None
    expires_at: datetime.datetime = None
    refresh_at: datetime.datetime = None
    created_at: datetime.datetime = None
    updated_at: datetime.datetime = None
    status: str = None
    version: int = 0
    data_signature: str = None
    shared_key_status: str = None
    is_public: bool = False
    is_encrypted: bool = True
    is_hidden: bool = False
    namespace_aware: bool = True
    is_binary: bool = False
    is_cached: bool = False
    shared_key_enc: str = None
    pub_key_cs: str = None
    encoding: str = None

    def parse_datetime(datetime_str):
        if datetime_str is not None:
            return parse(datetime_str)
        return None

    @staticmethod
    def from_json(json_str):
        data = json.loads(json_str)
        metadata = Metadata()
        metadata.ttl = data.get('ttl')
        metadata.ttb = data.get('ttb')
        metadata.ttr = data.get('ttr')
        metadata.ccd = data.get('ccd')
        metadata.created_by = data.get('createdBy')
        metadata.updated_by = data.get('updatedBy')
        metadata.available_at = Metadata.parse_datetime(data.get('availableAt'))
        metadata.expires_at = Metadata.parse_datetime(data.get('expiresAt'))
        metadata.refresh_at = Metadata.parse_datetime(data.get('refreshAt'))
        metadata.created_at = Metadata.parse_datetime(data.get('createdAt'))
        metadata.updated_at = Metadata.parse_datetime(data.get('updatedAt'))
        metadata.status = data.get('status')
        metadata.version = data.get('version')
        metadata.data_signature = data.get('dataSignature')
        metadata.shared_key_status = data.get('sharedKeyStatus')
        metadata.is_public = data.get('isPublic', False)
        metadata.is_encrypted = data.get('isEncrypted', True)
        metadata.is_hidden = data.get('isHidden', False)
        metadata.namespace_aware = data.get('namespaceAware', True)
        metadata.is_binary = data.get('isBinary', False)
        metadata.is_cached = data.get('isCached', False)
        metadata.shared_key_enc = data.get('sharedKeyEnc')
        metadata.pub_key_cs = data.get('pubKeyCS')
        metadata.encoding = data.get('encoding')
        return metadata


    def __str__(self):
        s = ""
        if self.ttl:
            s += f":ttl:{self.ttl}"
        if self.ttb:
            s += f":ttb:{self.ttb}"
        if self.ttr:
            s += f":ttr:{self.ttr}"
        if self.ccd:
            s += f":ccd:{self.ccd}"
        if self.data_signature:
            s += f":dataSignature:{self.data_signature}"
        if self.shared_key_status:
            s += f":sharedKeyStatus:{self.shared_key_status}"
        if self.shared_key_enc:
            s += f":sharedKeyEnc:{self.shared_key_enc}"
        if self.pub_key_cs:
            s += f":pubKeyCS:{self.pub_key_cs}"
        if self.is_binary:
            s += f":isBinary:{self.is_binary}"
        if self.is_encrypted:
            s += f":isEncrypted:{self.is_encrypted}"
        if self.encoding:
            s += f":encoding:{self.encoding}"
        return s

    @staticmethod
    def squash(first_metadata, second_metadata):
        metadata = Metadata()
        metadata.ttl = first_metadata.ttl if first_metadata.ttl is not None else second_metadata.ttl
        metadata.ttb = first_metadata.ttb if first_metadata.ttb is not None else second_metadata.ttb
        metadata.ttr = first_metadata.ttr if first_metadata.ttr is not None else second_metadata.ttr
        metadata.ccd = first_metadata.ccd if first_metadata.ccd is not None else second_metadata.ccd
        metadata.available_at = first_metadata.available_at if first_metadata.available_at is not None else second_metadata.available_at
        metadata.expires_at = first_metadata.expires_at if first_metadata.expires_at is not None else second_metadata.expires_at
        metadata.refresh_at = first_metadata.refresh_at if first_metadata.refresh_at is not None else second_metadata.refresh_at
        metadata.created_at = first_metadata.created_at if first_metadata.created_at is not None else second_metadata.created_at
        metadata.updated_at = first_metadata.updated_at if first_metadata.updated_at is not None else second_metadata.updated_at
        metadata.data_signature = first_metadata.data_signature if first_metadata.data_signature is not None else second_metadata.data_signature
        metadata.shared_key_status = first_metadata.shared_key_status if first_metadata.shared_key_status is not None else second_metadata.shared_key_status
        metadata.shared_key_enc = first_metadata.shared_key_enc if first_metadata.shared_key_enc is not None else second_metadata.shared_key_enc
        metadata.is_public = first_metadata.is_public if first_metadata.is_public is not None else second_metadata.is_public
        metadata.is_encrypted = first_metadata.is_encrypted if first_metadata.is_encrypted is not None else second_metadata.is_encrypted
        metadata.is_hidden = first_metadata.is_hidden if first_metadata.is_hidden is not None else second_metadata.is_hidden
        metadata.namespace_aware = first_metadata.namespace_aware if first_metadata.namespace_aware is not None else second_metadata.namespace_aware
        metadata.is_binary = first_metadata.is_binary if first_metadata.is_binary is not None else second_metadata.is_binary
        metadata.is_cached = first_metadata.is_cached if first_metadata.is_cached is not None else second_metadata.is_cached
        metadata.shared_key_enc = first_metadata.shared_key_enc if first_metadata.shared_key_enc is not None else second_metadata.shared_key_enc
        metadata.pub_key_cs = first_metadata.pub_key_cs if first_metadata.pub_key_cs is not None else second_metadata.pub_key_cs
        metadata.encoding = first_metadata.encoding if first_metadata.encoding is not None else second_metadata.encoding
        return metadata
