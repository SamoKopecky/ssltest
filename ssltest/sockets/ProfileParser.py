import logging

from ..core.utils import read_json

log = logging.getLogger(__name__)


class ProfileParser:
    network_profile_usage = read_json("network_profile_usage.json")
    network_profiles = read_json("network_profiles.json")

    @classmethod
    def parse(cls, usage):
        """
        Get a network profile from a usage

        :param str usage: Network usage
        :return: Network profile
        :rtype: tuple[int, float, float]
        """
        try:
            profile_name = cls.network_profile_usage[usage]
            profile = cls.network_profiles[profile_name]
        except KeyError:
            log.error("This key doesn't exist, returning default values")
            profile = cls.network_profiles["medium"]
        return (
            profile["retries_count"],
            profile["retry_interval"] / 1000,
            profile["timeout"] / 1000,
        )
