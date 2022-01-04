import logging
from os import rename
from os.path import expanduser, join
from pathlib import Path
from shutil import move
from typing import Dict, Optional, Union
from keyring.backends.macOS import Keyring as MacKeyring
from keyring.backends.Windows import WinVaultKeyring as WinKeyring
from keyring.credentials import SimpleCredential

from stai.util.config import load_config, save_config
from stai.util.default_root import DEFAULT_ROOT_PATH
from stai.util.file_keyring import FileKeyring
from stai.util.keychain import Keychain, CURRENT_KEY_VERSION, get_private_key_user, MAX_KEYS, bytes_to_mnemonic
from stai.util.keyring_wrapper import KeyringWrapper, LegacyKeyring, get_legacy_keyring_instance

log = logging.getLogger(__name__)


class StaicoinRenameMigration:
    previous_root: Path = Path(expanduser("~/.staicoin")).resolve()
    new_root: Path = Path(expanduser("~/.stai")).resolve()
    previous_root_mainnet: Path = Path(expanduser("~/.staicoin/mainnet")).resolve()
    new_root_mainnet: Path = Path(expanduser("~/.stai/mainnet")).resolve()

    def run(self):
        if not self._is_applicable():
            return
        log.warning("Applying migration: Renaming .staicoin to .stai ..")
        try:
            self._move_root_dir()
            self._migrate_ca_certs()
            self._migrate_config()
            self._migrate_keys()
            log.warning("Finished migration: Renaming .staicoin to .stai")
        except Exception:
            log.exception("Encountered an error during migration")

    def _is_applicable(self) -> bool:
        if not self.previous_root.exists():
            return False

        return not self.new_root.exists() or (self.previous_root_mainnet.exists() and not self.new_root_mainnet.exists())

    def _move_root_dir(self):
        if not self.new_root.exists():
            move(str(self.previous_root), str(self.new_root))
        else:
            move(str(self.previous_root_mainnet), str(self.new_root_mainnet))

    def _migrate_ca_certs(self):
        ca_path = join(self.new_root_mainnet, 'config', 'ssl', 'ca')
        if Path(join(ca_path, 'staicoin_ca.crt')).exists():
            rename(join(ca_path, 'staicoin_ca.crt'), join(ca_path, 'stai_ca.crt'))
        if Path(join(ca_path, 'staicoin_ca.key')).exists():
            rename(join(ca_path, 'staicoin_ca.key'), join(ca_path, 'stai_ca.key'))

    def _migrate_config(self):
        config: Dict = load_config(DEFAULT_ROOT_PATH, "config.yaml")
        if 'staicoin_ssl_ca' in config['harvester']:
            config['harvester']['stai_ssl_ca'] = config['harvester']['staicoin_ssl_ca']
            del config['harvester']['staicoin_ssl_ca']
        if config['harvester']['stai_ssl_ca']['crt'] == 'config/ssl/ca/staicoin_ca.crt':
            config['harvester']['stai_ssl_ca']['crt'] = 'config/ssl/ca/stai_ca.crt'
        if config['harvester']['stai_ssl_ca']['key'] == 'config/ssl/ca/staicoin_ca.key':
            config['harvester']['stai_ssl_ca']['key'] = 'config/ssl/ca/stai_ca.key'
        if 'staicoin_ssl_ca' in config:
            config['stai_ssl_ca'] = config['staicoin_ssl_ca']
            del config['staicoin_ssl_ca']
        if config['stai_ssl_ca']['crt'] == 'config/ssl/ca/staicoin_ca.crt':
            config['stai_ssl_ca']['crt'] = 'config/ssl/ca/stai_ca.crt'
        if config['stai_ssl_ca']['key'] == 'config/ssl/ca/staicoin_ca.key':
            config['stai_ssl_ca']['key'] = 'config/ssl/ca/stai_ca.key'
        save_config(DEFAULT_ROOT_PATH, "config.yaml", config)

    def _migrate_keys(self):
        old_user = f"user-staicoin-{CURRENT_KEY_VERSION}"
        old_service = f"staicoin-{old_user}"
        old_keychain = Keychain(user=old_user, service=old_service)
        old_keychain.keyring_wrapper.legacy_keyring = self._make_legacy_backend(
            old_keychain.keyring_wrapper,
            old_user,
            old_service
        )
        original_private_keys = old_keychain.get_all_private_keys()
        new_keychain = Keychain()
        # Force new keyring usage on migration
        new_keychain.keyring_wrapper.legacy_keyring = None
        for sk, seed in original_private_keys:
            assert seed is not None
            mnemonic = bytes_to_mnemonic(seed)
            new_keychain.add_private_key(mnemonic, '')

    def _make_legacy_backend(self, keyring_wrapper: KeyringWrapper, user: str, service: str) -> Optional[LegacyKeyring]:
        # If keyring.yaml isn't found or is empty, check if we're using
        # CryptFileKeyring, Mac Keychain, or Windows Credential Manager
        filekeyring = keyring_wrapper.keyring if type(keyring_wrapper.keyring) == FileKeyring else None
        if filekeyring and not filekeyring.has_content():
            keyring: Optional[LegacyKeyring] = get_legacy_keyring_instance()
            if keyring is not None and self._check_legacy_keyring_keys_present(
                keyring,
                user,
                service
            ):
                return keyring
        return None

    def _check_legacy_keyring_keys_present(
            self,
            keyring: Union[MacKeyring, WinKeyring],
            user: str,
            service: str
    ) -> bool:
        for index in range(0, MAX_KEYS):
            current_user: str = get_private_key_user(user, index)
            credential: Optional[SimpleCredential] = keyring.get_credential(service, current_user)
            if credential is not None:
                return True
        return False
