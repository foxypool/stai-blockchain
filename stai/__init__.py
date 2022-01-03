from pkg_resources import DistributionNotFound, get_distribution, resource_filename

from stai.migration.staicoin_rename import StaicoinRenameMigration

try:
    __version__ = get_distribution("stai-blockchain").version
except DistributionNotFound:
    # package is not installed
    __version__ = "unknown"

PYINSTALLER_SPEC_PATH = resource_filename("stai", "pyinstaller.spec")

StaicoinRenameMigration.run()
