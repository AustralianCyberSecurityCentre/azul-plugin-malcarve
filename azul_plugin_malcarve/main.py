"""Malcarve content extractor plugin.

This plugin carves and features obfuscated content from malware artifacts.
"""

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from malcarve_cbl import FormatEnum, FoundFormat
from malcarve_cbl.malcarve import carve_buffer


class AzulPluginMalcarve(BinaryPlugin):
    """Extract any obfuscated content."""

    VERSION = "2025.03.18"
    SETTINGS = add_settings(
        run_timeout=(int, 60 * 10),
        filter_max_content_size=(int, 10 * 1024 * 1024),  # process up to 10MB
        filter_data_types={"content": []},
    )
    FEATURES = [
        Feature("embedded_payload_type", desc="Type of payload found embedded in content", type=FeatureType.String),
        Feature("embedded_url", desc="URL found embedded in content", type=FeatureType.String),
        Feature("user_agent", desc="User-Agent found embedded in content", type=FeatureType.String),
        Feature("payload_obfuscation", desc="Type of obfuscation of embedded content", type=FeatureType.String),
        Feature(
            "payload_obfuscation_all",
            desc="List of all obfuscation types from the sample down to the payload",
            type=FeatureType.String,
        ),
        Feature(
            "obfuscation_key",
            desc="Little-endian hex bytes of key, used to deobfuscate payload",
            type=FeatureType.String,
        ),
        Feature(
            "obfuscation_key_size",
            desc="Length of key in bytes, used to deobfuscate payload",
            type=FeatureType.Integer,
        ),
        Feature(
            "obfuscation_incrementing_key",
            desc="How much the obfuscation key increments by each time it is applied",
            type=FeatureType.Integer,
        ),
        Feature(
            "obfuscation_ignores_zero",
            desc="If the obfuscation algorithm skips zeroed bytes according to its key size.",
            type=FeatureType.String,
        ),
        Feature(
            "obfuscation_scheme",
            desc="Obfuscation type, along with obfuscation key and details",
            type=FeatureType.String,
        ),
        Feature("tag", desc="Any informational label about the sample", type=FeatureType.String),
    ]

    def execute(self, job: Job) -> State:
        """Run across all file types looking for embedded content."""
        features: dict[str, FV] = {}

        data: bytes = job.get_data().read()
        max_depth: int = 4
        found_formats: list[FoundFormat] = carve_buffer(data, max_depth)

        for format in found_formats:
            if len(format.encoding_info.encodings_string) > 0:
                features.setdefault("payload_obfuscation_all", []).append(
                    FV(format.encoding_info.encodings_string, label=format.encoding_info.encoding_offsets_string)
                )

                if format.keyed_encoding is not None:
                    features.setdefault("obfuscation_scheme", []).append(
                        FV(
                            format.encoding_info.keyed_encoding_string,
                            label=format.encoding_info.encoding_offsets_string,
                        )
                    )

                    encoding = str(format.keyed_encoding.encoding).split(".")[-1].lower()

                    key_string = format.keyed_encoding.key.to_bytes(format.keyed_encoding.key_size, "little").hex()
                    key_string = "0x" + key_string.rjust(format.keyed_encoding.key_size, "0")
                    features.setdefault("obfuscation_key", []).append(
                        FV(key_string, label=format.encoding_info.encoding_offsets_string)
                    )
                    features.setdefault("obfuscation_key_size", []).append(
                        FV(format.keyed_encoding.key_size, label=format.encoding_info.encoding_offsets_string)
                    )
                    if format.keyed_encoding.increment != 0:
                        features.setdefault("obfuscation_incrementing_key", []).append(
                            FV(format.keyed_encoding.increment, label=format.encoding_info.encoding_offsets_string)
                        )
                    if format.keyed_encoding.ignore_zero:
                        features.setdefault("obfuscation_ignores_zero", []).append(
                            FV("true", label=format.encoding_info.encoding_offsets_string)
                        )

                else:
                    # use the encoding of the enclosing section if the payload isn't directly encoded with a key.
                    encoding: str = format.encoding_info.encodings_string.split("->")[-1]
                features.setdefault("payload_obfuscation", []).append(
                    FV(encoding, label=format.encoding_info.encoding_offsets_string)
                )

            features.setdefault("embedded_payload_type", []).append(
                FV(
                    value=str(format.type).split(".")[-1].lower(),
                    label=format.encoding_info.encoding_offsets_string,
                    offset=format.encoding_info.base_offset,
                    size=format.encoding_info.base_size,
                )
            )

            if format.type == FormatEnum.URL:
                features.setdefault("embedded_url", []).append(
                    FV(
                        value=format.content.decode(),
                        label=format.encoding_info.encoding_offsets_string,
                        offset=format.encoding_info.base_offset,
                        size=format.encoding_info.base_size,
                    )
                )
            elif format.type == FormatEnum.USER_AGENT:
                features.setdefault("user_agent", []).append(
                    FV(
                        value=format.content.decode(),
                        label=format.encoding_info.encoding_offsets_string,
                        offset=format.encoding_info.base_offset,
                        size=format.encoding_info.base_size,
                    )
                )
            else:
                # add the decoded content as a child entity
                relation = {}
                if format.encoding_info.base_offset is not None:
                    relation["offset"] = f"0x{format.encoding_info.base_offset:x}"
                if len(format.encoding_info.encodings_string) > 0:
                    if format.keyed_encoding:
                        relation["key"] = key_string
                    relation["action"] = "deobfuscated"
                    relation["obfuscation"] = format.encoding_info.encoding_offsets_string
                else:
                    relation["action"] = "extracted"
                child = self.add_child_with_data(relation, format.content)
                if len(format.encoding_info.encodings_string) > 0:
                    child.add_feature_values("tag", "deobfuscated_content")
        self.add_many_feature_values(features)
        return State(State.Label.COMPLETED)


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginMalcarve)


if __name__ == "__main__":
    main()
