"""Test cases for azul-plugin-malcarve plugin output."""

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_malcarve.main import AzulPluginMalcarve


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMalcarve

    def test_charcodes(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8938838db8d16708692e80d170e0d8dc1522531e5a5ab5ae878a27a147780f44",
                        "Malicious SGML, malware family ghostbuilder",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="8938838db8d16708692e80d170e0d8dc1522531e5a5ab5ae878a27a147780f44",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="charcodes(0x88f-0x9e06)->(0x0-0x3800)", offset=2191, size=38263),
                                FV(
                                    "pe",
                                    label="charcodes(0x9e35-0x297db)->reverse->(0x0-0xb400)",
                                    offset=40501,
                                    size=129446,
                                ),
                                FV("url", label="(0x23-0x56)", offset=35, size=51),
                                FV(
                                    "url",
                                    label="charcodes(0x9e35-0x297db)->reverse->(0xb164-0xb199)",
                                    offset=40501,
                                    size=129446,
                                ),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                                    label="charcodes(0x9e35-0x297db)->reverse->(0xb164-0xb199)",
                                    offset=40501,
                                    size=129446,
                                ),
                                FV(
                                    "http://schemas.microsoft.com/developer/msbuild/2003",
                                    label="(0x23-0x56)",
                                    offset=35,
                                    size=51,
                                ),
                            ],
                            "payload_obfuscation_all": [
                                FV("charcodes", label="charcodes(0x88f-0x9e06)->(0x0-0x3800)"),
                                FV("charcodes->reverse", label="charcodes(0x9e35-0x297db)->reverse->(0x0-0xb400)"),
                                FV("charcodes->reverse", label="charcodes(0x9e35-0x297db)->reverse->(0xb164-0xb199)"),
                            ],
                            "payload_obfuscation": [
                                FV("charcodes", label="charcodes(0x88f-0x9e06)->(0x0-0x3800)"),
                                FV("reverse", label="charcodes(0x9e35-0x297db)->reverse->(0x0-0xb400)"),
                                FV("reverse", label="charcodes(0x9e35-0x297db)->reverse->(0xb164-0xb199)"),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8938838db8d16708692e80d170e0d8dc1522531e5a5ab5ae878a27a147780f44",
                        ),
                        entity_type="binary",
                        entity_id="814f21f8c2befba504e592e3396be7454f93013939325cc7fbad5c38f022b395",
                        relationship={
                            "offset": "0x88f",
                            "action": "deobfuscated",
                            "obfuscation": "charcodes(0x88f-0x9e06)->(0x0-0x3800)",
                        },
                        data=[
                            EventData(
                                hash="814f21f8c2befba504e592e3396be7454f93013939325cc7fbad5c38f022b395",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8938838db8d16708692e80d170e0d8dc1522531e5a5ab5ae878a27a147780f44",
                        ),
                        entity_type="binary",
                        entity_id="1a7ceaddf547d47cf7d2d7eda0357d38f489eaeb3b06ea3027ae87df6e5c8195",
                        relationship={
                            "offset": "0x9e35",
                            "action": "deobfuscated",
                            "obfuscation": "charcodes(0x9e35-0x297db)->reverse->(0x0-0xb400)",
                        },
                        data=[
                            EventData(
                                hash="1a7ceaddf547d47cf7d2d7eda0357d38f489eaeb3b06ea3027ae87df6e5c8195",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={
                    "814f21f8c2befba504e592e3396be7454f93013939325cc7fbad5c38f022b395": b"",
                    "1a7ceaddf547d47cf7d2d7eda0357d38f489eaeb3b06ea3027ae87df6e5c8195": b"",
                },
            ),
        )

    def test_rolling_xor_pe(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "c08dbe159814900e43ea8e1b8bbc3b8a9b63a57d077b4d80289670b883e91bf2",
                        "PE hidden in a rolling XOR.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="c08dbe159814900e43ea8e1b8bbc3b8a9b63a57d077b4d80289670b883e91bf2",
                        features={
                            "embedded_payload_type": [FV("pe", label="rolling_xor(0x7-0x3007)", offset=7, size=12288)],
                            "payload_obfuscation": [FV("rolling_xor", label="rolling_xor(0x7-0x3007)")],
                            "payload_obfuscation_all": [FV("rolling_xor", label="rolling_xor(0x7-0x3007)")],
                            "obfuscation_key": [FV("0x0d", label="rolling_xor(0x7-0x3007)")],
                            "obfuscation_key_size": [FV(1, label="rolling_xor(0x7-0x3007)")],
                            "obfuscation_scheme": [
                                FV("rolling_xor(key:0x0d, bytes:1)", label="rolling_xor(0x7-0x3007)")
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="c08dbe159814900e43ea8e1b8bbc3b8a9b63a57d077b4d80289670b883e91bf2",
                        ),
                        entity_type="binary",
                        entity_id="8a8474143cbc5f6849db16664a510b2141830674943e33e02b783c2920ea2d8a",
                        relationship={
                            "offset": "0x7",
                            "key": "0x0d",
                            "action": "deobfuscated",
                            "obfuscation": "rolling_xor(0x7-0x3007)",
                        },
                        data=[
                            EventData(
                                hash="8a8474143cbc5f6849db16664a510b2141830674943e33e02b783c2920ea2d8a",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={"8a8474143cbc5f6849db16664a510b2141830674943e33e02b783c2920ea2d8a": b""},
            ),
        )

    def test_reversed_xor(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "50d8d48d5dc5107190fa0fd9e1d9b3a319d1badcddeb1b148449f7441f5a68a3",
                        "Malicious Windows 32EXE, payload encoded with reverse xor, malware family redline.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="50d8d48d5dc5107190fa0fd9e1d9b3a319d1badcddeb1b148449f7441f5a68a3",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="(0x0-0xffc00)", offset=0, size=1047552),
                                FV("pe", label="reverse->xor(0x1bb7b0-0x1ffdb0)"),
                                FV("url", label="(0xfefde-0xff007)", offset=1044446, size=41),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://www.w3.org/2001/XMLSchema-instance",
                                    label="(0xfefde-0xff007)",
                                    offset=1044446,
                                    size=41,
                                )
                            ],
                            "payload_obfuscation_all": [FV("reverse->xor", label="reverse->xor(0x1bb7b0-0x1ffdb0)")],
                            "obfuscation_scheme": [
                                FV("xor(key:0x0000000500, bytes:5)", label="reverse->xor(0x1bb7b0-0x1ffdb0)")
                            ],
                            "obfuscation_key": [FV("0x0000000500", label="reverse->xor(0x1bb7b0-0x1ffdb0)")],
                            "obfuscation_key_size": [FV(5, label="reverse->xor(0x1bb7b0-0x1ffdb0)")],
                            "payload_obfuscation": [FV("xor", label="reverse->xor(0x1bb7b0-0x1ffdb0)")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="50d8d48d5dc5107190fa0fd9e1d9b3a319d1badcddeb1b148449f7441f5a68a3",
                        ),
                        entity_type="binary",
                        entity_id="27ddc9b2dd5ff4c3bcdb3444b7912d93999694261c64db2b2492f859709e8e0e",
                        relationship={"offset": "0x0", "action": "extracted"},
                        data=[
                            EventData(
                                hash="27ddc9b2dd5ff4c3bcdb3444b7912d93999694261c64db2b2492f859709e8e0e",
                                label="content",
                            )
                        ],
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="50d8d48d5dc5107190fa0fd9e1d9b3a319d1badcddeb1b148449f7441f5a68a3",
                        ),
                        entity_type="binary",
                        entity_id="611fa395f0a24eeb12232e0337cc7cd41b3ea831e0cb7fa370a4d077170228ab",
                        relationship={
                            "key": "0x0000000500",
                            "action": "deobfuscated",
                            "obfuscation": "reverse->xor(0x1bb7b0-0x1ffdb0)",
                        },
                        data=[
                            EventData(
                                hash="611fa395f0a24eeb12232e0337cc7cd41b3ea831e0cb7fa370a4d077170228ab",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={
                    "27ddc9b2dd5ff4c3bcdb3444b7912d93999694261c64db2b2492f859709e8e0e": b"",
                    "611fa395f0a24eeb12232e0337cc7cd41b3ea831e0cb7fa370a4d077170228ab": b"",
                },
            ),
        )

    def test_charcode_overflow(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f691607006edcedd21d878b8d77bde839d2dad2940239f4217979e72fc21f6af",
                        "Malicious PDF, malware family phishingx.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f691607006edcedd21d878b8d77bde839d2dad2940239f4217979e72fc21f6af",
                        features={
                            "payload_obfuscation_all": [FV("deflate", label="deflate(0x1d868)->(0x3c0-0x409)")],
                            "payload_obfuscation": [FV("deflate", label="deflate(0x1d868)->(0x3c0-0x409)")],
                            "embedded_payload_type": [
                                FV("url", label="deflate(0x1d868)->(0x3c0-0x409)", offset=120936)
                            ],
                            "embedded_url": [
                                FV(
                                    "https://silverline.com.sg/private/SZ59020_JF_KOREA_Co_Ltd_Sales_Order.cab",
                                    label="deflate(0x1d868)->(0x3c0-0x409)",
                                    offset=120936,
                                )
                            ],
                        },
                    )
                ],
            ),
        )

    def test_plain(self):
        result = self.do_execution(data_in=[("content", b"blahblah\nhttp://test.com\nblahblah")])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="201e44079f65160598309b00ac3755c093ba8f1f54238e794789345a68b94f13",
                        features={
                            "embedded_payload_type": [FV("url", label="(0x9-0x18)", offset=9, size=15)],
                            "embedded_url": [FV("http://test.com", label="(0x9-0x18)", offset=9, size=15)],
                        },
                    )
                ],
            ),
        )

    def test_rolling_xor_url(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "c8a8f180139545863e50b493b4863e752d8786ce66bbe44228c564b50e2c8390",
                        "Payload encoded with a rolling XOR.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="c8a8f180139545863e50b493b4863e752d8786ce66bbe44228c564b50e2c8390",
                        features={
                            "embedded_payload_type": [
                                FV("url", label="rolling_xor(0x73eb0-0x73ed5)", offset=474800, size=37),
                                FV("url", label="rolling_xor(0x74b14-0x74b39)", offset=477972, size=37),
                                FV("url", label="rolling_xor(0x74de4-0x74e09)", offset=478692, size=37),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://d2z7qh5izenqp4.cloudfront.net/",
                                    label="rolling_xor(0x73eb0-0x73ed5)",
                                    offset=474800,
                                    size=37,
                                ),
                                FV(
                                    "http://d2z7qh5izenqp4.cloudfront.net/",
                                    label="rolling_xor(0x74b14-0x74b39)",
                                    offset=477972,
                                    size=37,
                                ),
                                FV(
                                    "http://d2z7qh5izenqp4.cloudfront.net/",
                                    label="rolling_xor(0x74de4-0x74e09)",
                                    offset=478692,
                                    size=37,
                                ),
                            ],
                            "obfuscation_key": [
                                FV("0x99", label="rolling_xor(0x73eb0-0x73ed5)"),
                                FV("0xac", label="rolling_xor(0x74b14-0x74b39)"),
                                FV("0xd4", label="rolling_xor(0x74de4-0x74e09)"),
                            ],
                            "obfuscation_key_size": [
                                FV("1", label="rolling_xor(0x73eb0-0x73ed5)"),
                                FV("1", label="rolling_xor(0x74b14-0x74b39)"),
                                FV("1", label="rolling_xor(0x74de4-0x74e09)"),
                            ],
                            "obfuscation_scheme": [
                                FV("rolling_xor(key:0x99, bytes:1)", label="rolling_xor(0x73eb0-0x73ed5)"),
                                FV("rolling_xor(key:0xac, bytes:1)", label="rolling_xor(0x74b14-0x74b39)"),
                                FV("rolling_xor(key:0xd4, bytes:1)", label="rolling_xor(0x74de4-0x74e09)"),
                            ],
                            "payload_obfuscation": [
                                FV("rolling_xor", label="rolling_xor(0x73eb0-0x73ed5)"),
                                FV("rolling_xor", label="rolling_xor(0x74b14-0x74b39)"),
                                FV("rolling_xor", label="rolling_xor(0x74de4-0x74e09)"),
                            ],
                            "payload_obfuscation_all": [
                                FV("rolling_xor", label="rolling_xor(0x73eb0-0x73ed5)"),
                                FV("rolling_xor", label="rolling_xor(0x74b14-0x74b39)"),
                                FV("rolling_xor", label="rolling_xor(0x74de4-0x74e09)"),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_rol_url(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "6465a6d23093b08a7db6d133e9f31c7dbbab3fbe6b8a75428f7a9c36b69abc7f",
                        "Benign data file path `Plants vs. Zombies/drm/content/Purchase/_common_assets/strings.xml.bin`",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="6465a6d23093b08a7db6d133e9f31c7dbbab3fbe6b8a75428f7a9c36b69abc7f",
                        features={
                            "embedded_payload_type": [FV("url", label="rol(0x197-0x1c6)", offset=407, size=47)],
                            "embedded_url": [
                                FV(
                                    "https://store.popcap.com/retrieve_order.php?a=r",
                                    label="rol(0x197-0x1c6)",
                                    offset=407,
                                    size=47,
                                )
                            ],
                            "payload_obfuscation": [FV("rol", label="rol(0x197-0x1c6)")],
                            "payload_obfuscation_all": [FV("rol", label="rol(0x197-0x1c6)")],
                            "obfuscation_key": [FV("0x01", label="rol(0x197-0x1c6)")],
                            "obfuscation_key_size": [FV(1, label="rol(0x197-0x1c6)")],
                            "obfuscation_scheme": [FV("rol(key:0x01, bytes:1)", label="rol(0x197-0x1c6)")],
                        },
                    )
                ],
            ),
        )

    def test_xor3(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "fa2c0695b0f560134a54daf9858f1b766803c4fc843f830953e1048715c22deb", "Malicious Windows DOS EXE"
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="fa2c0695b0f560134a54daf9858f1b766803c4fc843f830953e1048715c22deb",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="xor(0xa89-0x8889)", offset=2697, size=32256),
                                FV("url", label="(0x23912-0x23928)", offset=145682, size=22),
                                FV("url", label="(0x2394f-0x2397d)", offset=145743, size=46),
                                FV("url", label="(0x23cf3-0x23d06)", offset=146675, size=19),
                                FV("url", label="(0x23d2d-0x23d4e)", offset=146733, size=33),
                                FV("url", label="(0x24190-0x241ae)", offset=147856, size=30),
                                FV("url", label="(0x241bc-0x241e7)", offset=147900, size=43),
                                FV("url", label="(0x241fa-0x24225)", offset=147962, size=43),
                                FV("url", label="(0x24645-0x2465f)", offset=149061, size=26),
                                FV("url", label="(0x246ae-0x246c8)", offset=149166, size=26),
                                FV("url", label="(0x246d8-0x246f9)", offset=149208, size=33),
                                FV("url", label="(0x24736-0x24749)", offset=149302, size=19),
                                FV("url", label="(0x24757-0x24771)", offset=149335, size=26),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://crl.thawte.com/ThawteTimestampingCA.crl",
                                    label="(0x2394f-0x2397d)",
                                    offset=145743,
                                    size=46,
                                ),
                                FV("http://ocsp.thawte.com", label="(0x23912-0x23928)", offset=145682, size=22),
                                FV(
                                    "http://t1.symcb.com/ThawtePCA.crl",
                                    label="(0x23d2d-0x23d4e)",
                                    offset=146733,
                                    size=33,
                                ),
                                FV("http://t2.symcb.com", label="(0x23cf3-0x23d06)", offset=146675, size=19),
                                FV("http://tl.symcb.com/tl.crl", label="(0x24645-0x2465f)", offset=149061, size=26),
                                FV("http://tl.symcb.com/tl.crt", label="(0x24757-0x24771)", offset=149335, size=26),
                                FV("http://tl.symcd.com", label="(0x24736-0x24749)", offset=149302, size=19),
                                FV(
                                    "http://ts-aia.ws.symantec.com/tss-ca-g2.cer",
                                    label="(0x241bc-0x241e7)",
                                    offset=147900,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-crl.ws.symantec.com/tss-ca-g2.crl",
                                    label="(0x241fa-0x24225)",
                                    offset=147962,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-ocsp.ws.symantec.com", label="(0x24190-0x241ae)", offset=147856, size=30
                                ),
                                FV("https://www.thawte.com/cps", label="(0x246ae-0x246c8)", offset=149166, size=26),
                                FV(
                                    "https://www.thawte.com/repository",
                                    label="(0x246d8-0x246f9)",
                                    offset=149208,
                                    size=33,
                                ),
                            ],
                            "payload_obfuscation_all": [FV("xor", label="xor(0xa89-0x8889)")],
                            "obfuscation_scheme": [FV("xor(key:0x0000a0, bytes:3)", label="xor(0xa89-0x8889)")],
                            "obfuscation_key": [FV("0x0000a0", label="xor(0xa89-0x8889)")],
                            "obfuscation_key_size": [FV(3, label="xor(0xa89-0x8889)")],
                            "payload_obfuscation": [FV("xor", label="xor(0xa89-0x8889)")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="fa2c0695b0f560134a54daf9858f1b766803c4fc843f830953e1048715c22deb",
                        ),
                        entity_type="binary",
                        entity_id="f40150dd48454d9f1931ef0dd13b72ab1b841a81172142cfd1fa01b9de4b347f",
                        relationship={
                            "offset": "0xa89",
                            "key": "0x0000a0",
                            "action": "deobfuscated",
                            "obfuscation": "xor(0xa89-0x8889)",
                        },
                        data=[
                            EventData(
                                hash="f40150dd48454d9f1931ef0dd13b72ab1b841a81172142cfd1fa01b9de4b347f",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={"f40150dd48454d9f1931ef0dd13b72ab1b841a81172142cfd1fa01b9de4b347f": b""},
            ),
        )

    def test_add(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0ec8368e87b3dfc92141885a2930bdd99371526e09fc52b84b764c91c5fc47b8", "Unknown."
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="0ec8368e87b3dfc92141885a2930bdd99371526e09fc52b84b764c91c5fc47b8",
                        features={
                            "embedded_payload_type": [FV("url", label="(0x357c-0x359e)", offset=13692, size=34)],
                            "embedded_url": [
                                FV(
                                    "http://www.microsoft.com/exporting",
                                    label="(0x357c-0x359e)",
                                    offset=13692,
                                    size=34,
                                )
                            ],
                        },
                    )
                ],
            ),
        )

    def test_random(self):
        """Random base16 + base64 encoded data with no patterns"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e97d320ce354f983e55b13d1291190c6e9cfd905d001f45ca8b6b293accf990d",
                        "Random base16 + base64 encoded data with no patterns.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def test_hworm(self):
        """VBS with base64 encoded exes"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        "Malicious VBA file, hworm with base64 encoded exes as payload.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        features={
                            "embedded_payload_type": [
                                FV(
                                    "pe",
                                    label="base64(0x8ef6-0xc9fa)->deflate(0xa)->(0x0-0x6600)",
                                    offset=36598,
                                    size=15108,
                                ),
                                FV(
                                    "pe",
                                    label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x0-0x4e00)",
                                    offset=53236,
                                    size=11564,
                                ),
                                FV(
                                    "pe",
                                    label="base64(0xfd70-0x12820)->deflate(0xa)->(0x0-0x4a00)",
                                    offset=64880,
                                    size=10928,
                                ),
                                FV("url", label="(0x3dea-0x3e01)", offset=15850, size=23),
                                FV(
                                    "url",
                                    label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x4343-0x436c)",
                                    offset=53236,
                                    size=11564,
                                ),
                                FV(
                                    "url",
                                    label="base64(0xfd70-0x12820)->deflate(0xa)->(0x3f9b-0x3fc4)",
                                    offset=64880,
                                    size=10928,
                                ),
                                FV("user_agent", label="(0x3adb-0x3b4d)", offset=15067, size=114),
                                FV("user_agent", label="(0x3e3d-0x3eaf)", offset=15933, size=114),
                                FV("zip", label="base64(0x19096-0x2ad76)->(0x0-0xd5a8)", offset=102550, size=72928),
                            ],
                            "embedded_url": [
                                FV("http://ip-api.com/json/", label="(0x3dea-0x3e01)", offset=15850, size=23),
                                FV(
                                    "http://www.w3.org/2001/XMLSchema-instance",
                                    label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x4343-0x436c)",
                                    offset=53236,
                                    size=11564,
                                ),
                                FV(
                                    "http://www.w3.org/2001/XMLSchema-instance",
                                    label="base64(0xfd70-0x12820)->deflate(0xa)->(0x3f9b-0x3fc4)",
                                    offset=64880,
                                    size=10928,
                                ),
                            ],
                            "user_agent": [
                                FV(
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
                                    label="(0x3adb-0x3b4d)",
                                    offset=15067,
                                    size=114,
                                ),
                                FV(
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36",
                                    label="(0x3e3d-0x3eaf)",
                                    offset=15933,
                                    size=114,
                                ),
                            ],
                            "payload_obfuscation_all": [
                                FV("base64", label="base64(0x19096-0x2ad76)->(0x0-0xd5a8)"),
                                FV("base64->deflate", label="base64(0x8ef6-0xc9fa)->deflate(0xa)->(0x0-0x6600)"),
                                FV("base64->deflate", label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x0-0x4e00)"),
                                FV("base64->deflate", label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x4343-0x436c)"),
                                FV("base64->deflate", label="base64(0xfd70-0x12820)->deflate(0xa)->(0x0-0x4a00)"),
                                FV("base64->deflate", label="base64(0xfd70-0x12820)->deflate(0xa)->(0x3f9b-0x3fc4)"),
                            ],
                            "payload_obfuscation": [
                                FV("base64", label="base64(0x19096-0x2ad76)->(0x0-0xd5a8)"),
                                FV("deflate", label="base64(0x8ef6-0xc9fa)->deflate(0xa)->(0x0-0x6600)"),
                                FV("deflate", label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x0-0x4e00)"),
                                FV("deflate", label="base64(0xcff4-0xfd20)->deflate(0xa)->(0x4343-0x436c)"),
                                FV("deflate", label="base64(0xfd70-0x12820)->deflate(0xa)->(0x0-0x4a00)"),
                                FV("deflate", label="base64(0xfd70-0x12820)->deflate(0xa)->(0x3f9b-0x3fc4)"),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        ),
                        entity_type="binary",
                        entity_id="272e64291748fa8be01109faa46c0ea919bf4baf4924177ea6ac2ee0574f1c1a",
                        relationship={
                            "offset": "0x8ef6",
                            "action": "deobfuscated",
                            "obfuscation": "base64(0x8ef6-0xc9fa)->deflate(0xa)->(0x0-0x6600)",
                        },
                        data=[
                            EventData(
                                hash="272e64291748fa8be01109faa46c0ea919bf4baf4924177ea6ac2ee0574f1c1a",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        ),
                        entity_type="binary",
                        entity_id="d65a3033e440575a7d32f4399176e0cdb1b7e4efa108452fcdde658e90722653",
                        relationship={
                            "offset": "0xcff4",
                            "action": "deobfuscated",
                            "obfuscation": "base64(0xcff4-0xfd20)->deflate(0xa)->(0x0-0x4e00)",
                        },
                        data=[
                            EventData(
                                hash="d65a3033e440575a7d32f4399176e0cdb1b7e4efa108452fcdde658e90722653",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        ),
                        entity_type="binary",
                        entity_id="0421fab0c9260a7fe3361361581d84c000ed3057b9587eb4a97b6f5dc284a7af",
                        relationship={
                            "offset": "0xfd70",
                            "action": "deobfuscated",
                            "obfuscation": "base64(0xfd70-0x12820)->deflate(0xa)->(0x0-0x4a00)",
                        },
                        data=[
                            EventData(
                                hash="0421fab0c9260a7fe3361361581d84c000ed3057b9587eb4a97b6f5dc284a7af",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="8e0e65a6cb50aa3d26948758d200bf940aafcbdeed5959543eadbda4b342abe0",
                        ),
                        entity_type="binary",
                        entity_id="6f3cf374a1aa961be87dde5aaeb1706d95cdcadbd1a4c961363e5ff33fab168d",
                        relationship={
                            "offset": "0x19096",
                            "action": "deobfuscated",
                            "obfuscation": "base64(0x19096-0x2ad76)->(0x0-0xd5a8)",
                        },
                        data=[
                            EventData(
                                hash="6f3cf374a1aa961be87dde5aaeb1706d95cdcadbd1a4c961363e5ff33fab168d",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={
                    "272e64291748fa8be01109faa46c0ea919bf4baf4924177ea6ac2ee0574f1c1a": b"",
                    "d65a3033e440575a7d32f4399176e0cdb1b7e4efa108452fcdde658e90722653": b"",
                    "0421fab0c9260a7fe3361361581d84c000ed3057b9587eb4a97b6f5dc284a7af": b"",
                    "6f3cf374a1aa961be87dde5aaeb1706d95cdcadbd1a4c961363e5ff33fab168d": b"",
                },
            ),
        )

    def test_plain_lznt1(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        "Malicious Windows 32EXE, worm malware family virtool.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="lznt1(0x23244-0x2a6ee)", offset=143940, size=29866),
                                FV("pe", label="lznt1(0x2a6f0-0x6a73f)", offset=173808, size=262223),
                                FV("pe", label="lznt1(0x6a740-0x6f21f)", offset=436032, size=19167),
                                FV("pe", label="lznt1(0xb188-0x23244)", offset=45448, size=98492),
                            ],
                            "payload_obfuscation": [
                                FV("lznt1", label="lznt1(0x23244-0x2a6ee)"),
                                FV("lznt1", label="lznt1(0x2a6f0-0x6a73f)"),
                                FV("lznt1", label="lznt1(0x6a740-0x6f21f)"),
                                FV("lznt1", label="lznt1(0xb188-0x23244)"),
                            ],
                            "payload_obfuscation_all": [
                                FV("lznt1", label="lznt1(0x23244-0x2a6ee)"),
                                FV("lznt1", label="lznt1(0x2a6f0-0x6a73f)"),
                                FV("lznt1", label="lznt1(0x6a740-0x6f21f)"),
                                FV("lznt1", label="lznt1(0xb188-0x23244)"),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        ),
                        entity_type="binary",
                        entity_id="2d0bcc8dce0a65ec302bfe3a49c143ba852d50286893657674c6c7fe73b70bff",
                        relationship={
                            "offset": "0xb188",
                            "action": "deobfuscated",
                            "obfuscation": "lznt1(0xb188-0x23244)",
                        },
                        data=[
                            EventData(
                                hash="2d0bcc8dce0a65ec302bfe3a49c143ba852d50286893657674c6c7fe73b70bff",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        ),
                        entity_type="binary",
                        entity_id="1fa5dca1771d75940cd5364edb358d914baaefdc56f2d21d573bbce22d41b205",
                        relationship={
                            "offset": "0x23244",
                            "action": "deobfuscated",
                            "obfuscation": "lznt1(0x23244-0x2a6ee)",
                        },
                        data=[
                            EventData(
                                hash="1fa5dca1771d75940cd5364edb358d914baaefdc56f2d21d573bbce22d41b205",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        ),
                        entity_type="binary",
                        entity_id="d65d3acf805651b38ec3c6eee1fb4efa83824fdd7e407495cdb9f6ad9b8e0c7d",
                        relationship={
                            "offset": "0x2a6f0",
                            "action": "deobfuscated",
                            "obfuscation": "lznt1(0x2a6f0-0x6a73f)",
                        },
                        data=[
                            EventData(
                                hash="d65d3acf805651b38ec3c6eee1fb4efa83824fdd7e407495cdb9f6ad9b8e0c7d",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="7bd7296e7dd38e6e23c4e11a9723e956be251a4142407676d84240541d3d37f1",
                        ),
                        entity_type="binary",
                        entity_id="18ec72076fb151ad97aeaa5e18d357aeb77c405dd867703e6709b9ede40cb237",
                        relationship={
                            "offset": "0x6a740",
                            "action": "deobfuscated",
                            "obfuscation": "lznt1(0x6a740-0x6f21f)",
                        },
                        data=[
                            EventData(
                                hash="18ec72076fb151ad97aeaa5e18d357aeb77c405dd867703e6709b9ede40cb237",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={
                    "2d0bcc8dce0a65ec302bfe3a49c143ba852d50286893657674c6c7fe73b70bff": b"",
                    "1fa5dca1771d75940cd5364edb358d914baaefdc56f2d21d573bbce22d41b205": b"",
                    "d65d3acf805651b38ec3c6eee1fb4efa83824fdd7e407495cdb9f6ad9b8e0c7d": b"",
                    "18ec72076fb151ad97aeaa5e18d357aeb77c405dd867703e6709b9ede40cb237": b"",
                },
            ),
        )

    def test_gameover_zeus_lznt1(self):
        """XOR encoded lznt1 compressed"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9220bf9868b53018dbd9a76ff2044ddfe604c0241ec890a3071f4a5162c3c825",
                        "Malicious file with a Zeus payload.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9220bf9868b53018dbd9a76ff2044ddfe604c0241ec890a3071f4a5162c3c825",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)", offset=4, size=289554)
                            ],
                            "payload_obfuscation": [FV("xor", label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)")],
                            "payload_obfuscation_all": [
                                FV("xor->lznt1", label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)")
                            ],
                            "obfuscation_key": [FV("0x3eef388f", label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)")],
                            "obfuscation_key_size": [FV(4, label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)")],
                            "obfuscation_scheme": [
                                FV("xor(key:0x3eef388f, bytes:4)", label="xor(0x4-0x46b16)->lznt1(0x0-0x46b12)")
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="9220bf9868b53018dbd9a76ff2044ddfe604c0241ec890a3071f4a5162c3c825",
                        ),
                        entity_type="binary",
                        entity_id="b7a755646d17c7fff3ed92fd9c5e34a5d0f93fb6dcb1c3e5246c6e3915cdff1a",
                        relationship={
                            "offset": "0x4",
                            "key": "0x3eef388f",
                            "action": "deobfuscated",
                            "obfuscation": "xor(0x4-0x46b16)->lznt1(0x0-0x46b12)",
                        },
                        data=[
                            EventData(
                                hash="b7a755646d17c7fff3ed92fd9c5e34a5d0f93fb6dcb1c3e5246c6e3915cdff1a",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("deobfuscated_content")]},
                    ),
                ],
                data={"b7a755646d17c7fff3ed92fd9c5e34a5d0f93fb6dcb1c3e5246c6e3915cdff1a": b""},
            ),
        )

    def test_macro_url(self):
        """VBA with base64 encoded url"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "181aeaed1d4b5107d42809cf519b6b1f8719b64491900295dce952aa163858a2",
                        "Malicious VBA, with base64 encoded malicious url.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="181aeaed1d4b5107d42809cf519b6b1f8719b64491900295dce952aa163858a2",
                        features={
                            "payload_obfuscation_all": [FV("base64", label="base64(0x1a6-0x1f2)->(0x0-0x38)")],
                            "payload_obfuscation": [FV("base64", label="base64(0x1a6-0x1f2)->(0x0-0x38)")],
                            "embedded_payload_type": [
                                FV("url", label="base64(0x1a6-0x1f2)->(0x0-0x38)", offset=422, size=76)
                            ],
                            "embedded_url": [
                                FV(
                                    "http://nandaheritage.com/wp-admin/includes/Fud222222.exe",
                                    label="base64(0x1a6-0x1f2)->(0x0-0x38)",
                                    offset=422,
                                    size=76,
                                )
                            ],
                        },
                    )
                ],
            ),
        )

    def test_reverse_url(self):
        """Exe with reversed url"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f42a03109b75c236fa11edb290a7ebda8f8d32453f26a77710f12ff33d2ba797",
                        "Malicious Windows 32EXE reverse URL.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f42a03109b75c236fa11edb290a7ebda8f8d32453f26a77710f12ff33d2ba797",
                        features={
                            "payload_obfuscation_all": [FV("reverse", label="reverse->(0x1cec6-0x1cedc)")],
                            "payload_obfuscation": [FV("reverse", label="reverse->(0x1cec6-0x1cedc)")],
                            "embedded_payload_type": [FV("url", label="reverse->(0x1cec6-0x1cedc)")],
                            "embedded_url": [FV("http://bit.do/qatybnpo", label="reverse->(0x1cec6-0x1cedc)")],
                        },
                    )
                ],
            ),
        )

    def test_incrementing_xor(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "c2c1ef904a2ef997d21e24a845a280fb202b130bf08fcdf59c727f13019b1f59",
                        "Malicious Windows 32EXE, malware family CobaltStrike",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="c2c1ef904a2ef997d21e24a845a280fb202b130bf08fcdf59c727f13019b1f59",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="(0x0-0x61c00)", offset=0, size=400384),
                                FV(
                                    "url",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)",
                                    offset=84992,
                                    size=3712,
                                ),
                                FV(
                                    "user_agent",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)",
                                    offset=84992,
                                    size=3712,
                                ),
                            ],
                            "payload_obfuscation_all": [
                                FV(
                                    "base64->base16->xor",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)",
                                ),
                                FV(
                                    "base64->base16->xor",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)",
                                ),
                            ],
                            "obfuscation_scheme": [
                                FV(
                                    "xor(key:0x6d, bytes:1, increment:19)",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)",
                                ),
                                FV(
                                    "xor(key:0x8c, bytes:1, increment:19)",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)",
                                ),
                            ],
                            "obfuscation_key": [
                                FV("0x6d", label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)"),
                                FV("0x8c", label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)"),
                            ],
                            "obfuscation_key_size": [
                                FV(1, label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)"),
                                FV(1, label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)"),
                            ],
                            "obfuscation_incrementing_key": [
                                FV(19, label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)"),
                                FV(19, label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)"),
                            ],
                            "payload_obfuscation": [
                                FV("xor", label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)"),
                                FV("xor", label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)"),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://code.jquery.com/",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x26c-0x283)",
                                    offset=84992,
                                    size=3712,
                                )
                            ],
                            "user_agent": [
                                FV(
                                    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
                                    label="base64(0x14c00-0x15a80)->base16(0x0-0xadf)->xor(0x2b1-0x2ee)",
                                    offset=84992,
                                    size=3712,
                                )
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="c2c1ef904a2ef997d21e24a845a280fb202b130bf08fcdf59c727f13019b1f59",
                        ),
                        entity_type="binary",
                        entity_id="bcc8bafe17b5c854529ee7bb96938e37d09c711eed3d0e76308d3ecda096b271",
                        relationship={"offset": "0x0", "action": "extracted"},
                        data=[
                            EventData(
                                hash="bcc8bafe17b5c854529ee7bb96938e37d09c711eed3d0e76308d3ecda096b271",
                                label="content",
                            )
                        ],
                    ),
                ],
                data={"bcc8bafe17b5c854529ee7bb96938e37d09c711eed3d0e76308d3ecda096b271": b""},
            ),
        )

    def test_dupe_children(self):
        """Test handling of duplicate extracted children."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "c0af4d1ea624b223ebf5d38e40d513c29623e50b4ab69121b4c0073fe3bc9f23",
                        "Malicious Windows 32EXE, has duplicate child payloads.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="c0af4d1ea624b223ebf5d38e40d513c29623e50b4ab69121b4c0073fe3bc9f23",
                        features={
                            "embedded_payload_type": [
                                FV("pe", label="(0x0-0x3945)", offset=0, size=14661),
                                FV("pe", label="(0x125a3-0x15ee8)", offset=75171, size=14661),
                                FV("pe", label="(0x15fa2-0x183a2)", offset=90018, size=9216),
                                FV("pe", label="(0x19d49-0x3b949)", offset=105801, size=138240),
                                FV("pe", label="(0x2fb0e-0x33453)", offset=195342, size=14661),
                                FV("pe", label="(0x3350d-0x36e52)", offset=210189, size=14661),
                                FV("pe", label="(0x36f0c-0x3930c)", offset=225036, size=9216),
                                FV("pe", label="(0x39ff-0x7344)", offset=14847, size=14661),
                                FV("pe", label="(0x3acb3-0x3e5f8)", offset=240819, size=14661),
                                FV("pe", label="(0x3e6b2-0x41ff7)", offset=255666, size=14661),
                                FV("pe", label="(0x420b1-0x459f6)", offset=270513, size=14661),
                                FV("pe", label="(0x45ab0-0x47eb0)", offset=285360, size=9216),
                                FV("pe", label="(0x73fe-0x97fe)", offset=29694, size=9216),
                                FV("pe", label="(0xb1a5-0xeaea)", offset=45477, size=14661),
                                FV("pe", label="(0xeba4-0x124e9)", offset=60324, size=14661),
                                FV("url", label="(0x17f46-0x17f7b)", offset=98118, size=53),
                                FV("url", label="(0x186e4-0x186fa)", offset=100068, size=22),
                                FV("url", label="(0x18721-0x1874f)", offset=100129, size=46),
                                FV("url", label="(0x18ac5-0x18ae3)", offset=101061, size=30),
                                FV("url", label="(0x18af1-0x18b1c)", offset=101105, size=43),
                                FV("url", label="(0x18b2f-0x18b5a)", offset=101167, size=43),
                                FV("url", label="(0x18d6b-0x18d87)", offset=101739, size=28),
                                FV("url", label="(0x19014-0x19043)", offset=102420, size=47),
                                FV("url", label="(0x1906d-0x19089)", offset=102509, size=28),
                                FV("url", label="(0x190bc-0x190d4)", offset=102588, size=24),
                                FV("url", label="(0x190e2-0x19111)", offset=102626, size=47),
                                FV("url", label="(0x193f1-0x1940d)", offset=103409, size=28),
                                FV("url", label="(0x195af-0x195cb)", offset=103855, size=28),
                                FV("url", label="(0x195db-0x195f7)", offset=103899, size=28),
                                FV("url", label="(0x19653-0x19678)", offset=104019, size=37),
                                FV("url", label="(0x19689-0x196ac)", offset=104073, size=35),
                                FV("url", label="(0x196ca-0x196e2)", offset=104138, size=24),
                                FV("url", label="(0x198f2-0x1990e)", offset=104690, size=28),
                                FV("url", label="(0x38eb0-0x38ee5)", offset=233136, size=53),
                                FV("url", label="(0x3964e-0x39664)", offset=235086, size=22),
                                FV("url", label="(0x3968b-0x396b9)", offset=235147, size=46),
                                FV("url", label="(0x39a2f-0x39a4d)", offset=236079, size=30),
                                FV("url", label="(0x39a5b-0x39a86)", offset=236123, size=43),
                                FV("url", label="(0x39a99-0x39ac4)", offset=236185, size=43),
                                FV("url", label="(0x39cd5-0x39cf1)", offset=236757, size=28),
                                FV("url", label="(0x39f7e-0x39fad)", offset=237438, size=47),
                                FV("url", label="(0x39fd7-0x39ff3)", offset=237527, size=28),
                                FV("url", label="(0x3a026-0x3a03e)", offset=237606, size=24),
                                FV("url", label="(0x3a04c-0x3a07b)", offset=237644, size=47),
                                FV("url", label="(0x3a35b-0x3a377)", offset=238427, size=28),
                                FV("url", label="(0x3a519-0x3a535)", offset=238873, size=28),
                                FV("url", label="(0x3a545-0x3a561)", offset=238917, size=28),
                                FV("url", label="(0x3a5bd-0x3a5e2)", offset=239037, size=37),
                                FV("url", label="(0x3a5f3-0x3a616)", offset=239091, size=35),
                                FV("url", label="(0x3a634-0x3a64c)", offset=239156, size=24),
                                FV("url", label="(0x3a85c-0x3a878)", offset=239708, size=28),
                                FV("url", label="(0x47a54-0x47a89)", offset=293460, size=53),
                                FV("url", label="(0x481f2-0x48208)", offset=295410, size=22),
                                FV("url", label="(0x4822f-0x4825d)", offset=295471, size=46),
                                FV("url", label="(0x485d3-0x485f1)", offset=296403, size=30),
                                FV("url", label="(0x485ff-0x4862a)", offset=296447, size=43),
                                FV("url", label="(0x4863d-0x48668)", offset=296509, size=43),
                                FV("url", label="(0x48879-0x48895)", offset=297081, size=28),
                                FV("url", label="(0x48b22-0x48b51)", offset=297762, size=47),
                                FV("url", label="(0x48b7b-0x48b97)", offset=297851, size=28),
                                FV("url", label="(0x48bca-0x48be2)", offset=297930, size=24),
                                FV("url", label="(0x48bf0-0x48c1f)", offset=297968, size=47),
                                FV("url", label="(0x48eff-0x48f1b)", offset=298751, size=28),
                                FV("url", label="(0x490bd-0x490d9)", offset=299197, size=28),
                                FV("url", label="(0x490e9-0x49105)", offset=299241, size=28),
                                FV("url", label="(0x49161-0x49186)", offset=299361, size=37),
                                FV("url", label="(0x49197-0x491ba)", offset=299415, size=35),
                                FV("url", label="(0x491d8-0x491f0)", offset=299480, size=24),
                                FV("url", label="(0x49400-0x4941c)", offset=300032, size=28),
                                FV("url", label="(0x93a2-0x93d7)", offset=37794, size=53),
                                FV("url", label="(0x9b40-0x9b56)", offset=39744, size=22),
                                FV("url", label="(0x9b7d-0x9bab)", offset=39805, size=46),
                                FV("url", label="(0x9f21-0x9f3f)", offset=40737, size=30),
                                FV("url", label="(0x9f4d-0x9f78)", offset=40781, size=43),
                                FV("url", label="(0x9f8b-0x9fb6)", offset=40843, size=43),
                                FV("url", label="(0xa1c7-0xa1e3)", offset=41415, size=28),
                                FV("url", label="(0xa470-0xa49f)", offset=42096, size=47),
                                FV("url", label="(0xa4c9-0xa4e5)", offset=42185, size=28),
                                FV("url", label="(0xa518-0xa530)", offset=42264, size=24),
                                FV("url", label="(0xa53e-0xa56d)", offset=42302, size=47),
                                FV("url", label="(0xa84d-0xa869)", offset=43085, size=28),
                                FV("url", label="(0xaa0b-0xaa27)", offset=43531, size=28),
                                FV("url", label="(0xaa37-0xaa53)", offset=43575, size=28),
                                FV("url", label="(0xaaaf-0xaad4)", offset=43695, size=37),
                                FV("url", label="(0xaae5-0xab08)", offset=43749, size=35),
                                FV("url", label="(0xab26-0xab3e)", offset=43814, size=24),
                                FV("url", label="(0xad4e-0xad6a)", offset=44366, size=28),
                            ],
                            "embedded_url": [
                                FV(
                                    "http://crl.thawte.com/ThawteTimestampingCA.crl",
                                    label="(0x18721-0x1874f)",
                                    offset=100129,
                                    size=46,
                                ),
                                FV(
                                    "http://crl.thawte.com/ThawteTimestampingCA.crl",
                                    label="(0x3968b-0x396b9)",
                                    offset=235147,
                                    size=46,
                                ),
                                FV(
                                    "http://crl.thawte.com/ThawteTimestampingCA.crl",
                                    label="(0x4822f-0x4825d)",
                                    offset=295471,
                                    size=46,
                                ),
                                FV(
                                    "http://crl.thawte.com/ThawteTimestampingCA.crl",
                                    label="(0x9b7d-0x9bab)",
                                    offset=39805,
                                    size=46,
                                ),
                                FV(
                                    "http://crl.verisign.com/pca3-g5.crl",
                                    label="(0x19689-0x196ac)",
                                    offset=104073,
                                    size=35,
                                ),
                                FV(
                                    "http://crl.verisign.com/pca3-g5.crl",
                                    label="(0x3a5f3-0x3a616)",
                                    offset=239091,
                                    size=35,
                                ),
                                FV(
                                    "http://crl.verisign.com/pca3-g5.crl",
                                    label="(0x49197-0x491ba)",
                                    offset=299415,
                                    size=35,
                                ),
                                FV(
                                    "http://crl.verisign.com/pca3-g5.crl",
                                    label="(0xaae5-0xab08)",
                                    offset=43749,
                                    size=35,
                                ),
                                FV(
                                    "http://csc3-2010-aia.verisign.com/CSC3-2010.cer",
                                    label="(0x190e2-0x19111)",
                                    offset=102626,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-aia.verisign.com/CSC3-2010.cer",
                                    label="(0x3a04c-0x3a07b)",
                                    offset=237644,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-aia.verisign.com/CSC3-2010.cer",
                                    label="(0x48bf0-0x48c1f)",
                                    offset=297968,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-aia.verisign.com/CSC3-2010.cer",
                                    label="(0xa53e-0xa56d)",
                                    offset=42302,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-crl.verisign.com/CSC3-2010.crl",
                                    label="(0x19014-0x19043)",
                                    offset=102420,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-crl.verisign.com/CSC3-2010.crl",
                                    label="(0x39f7e-0x39fad)",
                                    offset=237438,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-crl.verisign.com/CSC3-2010.crl",
                                    label="(0x48b22-0x48b51)",
                                    offset=297762,
                                    size=47,
                                ),
                                FV(
                                    "http://csc3-2010-crl.verisign.com/CSC3-2010.crl",
                                    label="(0xa470-0xa49f)",
                                    offset=42096,
                                    size=47,
                                ),
                                FV(
                                    "http://logo.verisign.com/vslogo.gif04",
                                    label="(0x19653-0x19678)",
                                    offset=104019,
                                    size=37,
                                ),
                                FV(
                                    "http://logo.verisign.com/vslogo.gif04",
                                    label="(0x3a5bd-0x3a5e2)",
                                    offset=239037,
                                    size=37,
                                ),
                                FV(
                                    "http://logo.verisign.com/vslogo.gif04",
                                    label="(0x49161-0x49186)",
                                    offset=299361,
                                    size=37,
                                ),
                                FV(
                                    "http://logo.verisign.com/vslogo.gif04",
                                    label="(0xaaaf-0xaad4)",
                                    offset=43695,
                                    size=37,
                                ),
                                FV("http://ocsp.thawte.com", label="(0x186e4-0x186fa)", offset=100068, size=22),
                                FV("http://ocsp.thawte.com", label="(0x3964e-0x39664)", offset=235086, size=22),
                                FV("http://ocsp.thawte.com", label="(0x481f2-0x48208)", offset=295410, size=22),
                                FV("http://ocsp.thawte.com", label="(0x9b40-0x9b56)", offset=39744, size=22),
                                FV("http://ocsp.verisign.com", label="(0x190bc-0x190d4)", offset=102588, size=24),
                                FV("http://ocsp.verisign.com", label="(0x196ca-0x196e2)", offset=104138, size=24),
                                FV("http://ocsp.verisign.com", label="(0x3a026-0x3a03e)", offset=237606, size=24),
                                FV("http://ocsp.verisign.com", label="(0x3a634-0x3a64c)", offset=239156, size=24),
                                FV("http://ocsp.verisign.com", label="(0x48bca-0x48be2)", offset=297930, size=24),
                                FV("http://ocsp.verisign.com", label="(0x491d8-0x491f0)", offset=299480, size=24),
                                FV("http://ocsp.verisign.com", label="(0xa518-0xa530)", offset=42264, size=24),
                                FV("http://ocsp.verisign.com", label="(0xab26-0xab3e)", offset=43814, size=24),
                                FV(
                                    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                                    label="(0x17f46-0x17f7b)",
                                    offset=98118,
                                    size=53,
                                ),
                                FV(
                                    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                                    label="(0x38eb0-0x38ee5)",
                                    offset=233136,
                                    size=53,
                                ),
                                FV(
                                    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                                    label="(0x47a54-0x47a89)",
                                    offset=293460,
                                    size=53,
                                ),
                                FV(
                                    "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
                                    label="(0x93a2-0x93d7)",
                                    offset=37794,
                                    size=53,
                                ),
                                FV(
                                    "http://ts-aia.ws.symantec.com/tss-ca-g2.cer",
                                    label="(0x18af1-0x18b1c)",
                                    offset=101105,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-aia.ws.symantec.com/tss-ca-g2.cer",
                                    label="(0x39a5b-0x39a86)",
                                    offset=236123,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-aia.ws.symantec.com/tss-ca-g2.cer",
                                    label="(0x485ff-0x4862a)",
                                    offset=296447,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-aia.ws.symantec.com/tss-ca-g2.cer",
                                    label="(0x9f4d-0x9f78)",
                                    offset=40781,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-crl.ws.symantec.com/tss-ca-g2.crl",
                                    label="(0x18b2f-0x18b5a)",
                                    offset=101167,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-crl.ws.symantec.com/tss-ca-g2.crl",
                                    label="(0x39a99-0x39ac4)",
                                    offset=236185,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-crl.ws.symantec.com/tss-ca-g2.crl",
                                    label="(0x4863d-0x48668)",
                                    offset=296509,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-crl.ws.symantec.com/tss-ca-g2.crl",
                                    label="(0x9f8b-0x9fb6)",
                                    offset=40843,
                                    size=43,
                                ),
                                FV(
                                    "http://ts-ocsp.ws.symantec.com", label="(0x18ac5-0x18ae3)", offset=101061, size=30
                                ),
                                FV(
                                    "http://ts-ocsp.ws.symantec.com", label="(0x39a2f-0x39a4d)", offset=236079, size=30
                                ),
                                FV(
                                    "http://ts-ocsp.ws.symantec.com", label="(0x485d3-0x485f1)", offset=296403, size=30
                                ),
                                FV("http://ts-ocsp.ws.symantec.com", label="(0x9f21-0x9f3f)", offset=40737, size=30),
                                FV("https://www.verisign.com/cps", label="(0x195af-0x195cb)", offset=103855, size=28),
                                FV("https://www.verisign.com/cps", label="(0x3a519-0x3a535)", offset=238873, size=28),
                                FV("https://www.verisign.com/cps", label="(0x490bd-0x490d9)", offset=299197, size=28),
                                FV("https://www.verisign.com/cps", label="(0xaa0b-0xaa27)", offset=43531, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x18d6b-0x18d87)", offset=101739, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x1906d-0x19089)", offset=102509, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x193f1-0x1940d)", offset=103409, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x195db-0x195f7)", offset=103899, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x198f2-0x1990e)", offset=104690, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x39cd5-0x39cf1)", offset=236757, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x39fd7-0x39ff3)", offset=237527, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x3a35b-0x3a377)", offset=238427, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x3a545-0x3a561)", offset=238917, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x3a85c-0x3a878)", offset=239708, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x48879-0x48895)", offset=297081, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x48b7b-0x48b97)", offset=297851, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x48eff-0x48f1b)", offset=298751, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x490e9-0x49105)", offset=299241, size=28),
                                FV("https://www.verisign.com/rpa", label="(0x49400-0x4941c)", offset=300032, size=28),
                                FV("https://www.verisign.com/rpa", label="(0xa1c7-0xa1e3)", offset=41415, size=28),
                                FV("https://www.verisign.com/rpa", label="(0xa4c9-0xa4e5)", offset=42185, size=28),
                                FV("https://www.verisign.com/rpa", label="(0xa84d-0xa869)", offset=43085, size=28),
                                FV("https://www.verisign.com/rpa", label="(0xaa37-0xaa53)", offset=43575, size=28),
                                FV("https://www.verisign.com/rpa", label="(0xad4e-0xad6a)", offset=44366, size=28),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="c0af4d1ea624b223ebf5d38e40d513c29623e50b4ab69121b4c0073fe3bc9f23",
                        ),
                        entity_type="binary",
                        entity_id="ade6ff26af4e1c1ac3e5f75ef727c7f72ee96381c7ef6793074cc82c95f8d0be",
                        relationship={"offset": "0x0", "action": "extracted"},
                        data=[
                            EventData(
                                hash="ade6ff26af4e1c1ac3e5f75ef727c7f72ee96381c7ef6793074cc82c95f8d0be",
                                label="content",
                            )
                        ],
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="c0af4d1ea624b223ebf5d38e40d513c29623e50b4ab69121b4c0073fe3bc9f23",
                        ),
                        entity_type="binary",
                        entity_id="0187fe53b290201f369698733e607cd8dda055ab8788173c2527a55b54dadf79",
                        relationship={"offset": "0x73fe", "action": "extracted"},
                        data=[
                            EventData(
                                hash="0187fe53b290201f369698733e607cd8dda055ab8788173c2527a55b54dadf79",
                                label="content",
                            )
                        ],
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="c0af4d1ea624b223ebf5d38e40d513c29623e50b4ab69121b4c0073fe3bc9f23",
                        ),
                        entity_type="binary",
                        entity_id="78dacf6053b7c1719847319fc96dd6ea24d9772557d7f0fe40dc1eeddef0b39a",
                        relationship={"offset": "0x19d49", "action": "extracted"},
                        data=[
                            EventData(
                                hash="78dacf6053b7c1719847319fc96dd6ea24d9772557d7f0fe40dc1eeddef0b39a",
                                label="content",
                            )
                        ],
                    ),
                ],
                data={
                    "ade6ff26af4e1c1ac3e5f75ef727c7f72ee96381c7ef6793074cc82c95f8d0be": b"",
                    "0187fe53b290201f369698733e607cd8dda055ab8788173c2527a55b54dadf79": b"",
                    "78dacf6053b7c1719847319fc96dd6ea24d9772557d7f0fe40dc1eeddef0b39a": b"",
                },
            ),
        )
