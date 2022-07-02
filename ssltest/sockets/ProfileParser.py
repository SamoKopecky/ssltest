import logging

from ..core.utils import read_json

network_profile_usage = read_json('network_profile_usage.json')
network_profiles = read_json('network_profiles.json')

log = logging.getLogger(__name__)


class ProfileParser:

    @staticmethod
    def parse(usage):
        try:
            profile_name = network_profile_usage[usage]
            profile = network_profiles[profile_name]
        except KeyError:
            log.error('This key doesn\'t exist, returning default values')
            profile = network_profiles['medium']
        return (
            profile['retries_count'],
            profile['retry_interval'] / 1000,
            profile['timeout'] / 1000
        )
