package browser

import (
	"github.com/smallerqiu/fhttp/http2"
	tls "github.com/smallerqiu/utls"
)

var Custom = ClientProfile{
	// 对标chrome 108.0
	clientHelloId: tls.ClientHelloID{
		Client:               "Custom",
		RandomExtensionOrder: false,
		Version:              "14.5",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS12,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_256_GCM_SHA384,                        //4866
					tls.TLS_AES_128_GCM_SHA256,                        //4865
					tls.TLS_CHACHA20_POLY1305_SHA256,                  // 5867
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       //49196
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       //49195
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, //52393
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         //49200
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   //52392
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         //49199
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            //49172
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            //49171
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               //157
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               //156
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  //53
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  //47
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},           //0 , server_name
					&tls.StatusRequestExtension{}, //5 ,status_request
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ //10 ,supported_groups
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256, //23
						tls.CurveP384, //24
						tls.CurveP521, //25
						30,
						256,
						257,
						258,
						259,
						260,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{ //11 ,ec_point_formats
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //16 ,application_layer_protocol_negotiation
					&tls.StatusRequestV2Extension{},                               //17
					&tls.ExtendedMasterSecretExtension{},                          //23 ,extended_master_secret
					&tls.SessionTicketExtension{},                                 // 35  ,session_ticket
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ //13 ,signature_algorithms
						tls.ECDSAWithP256AndSHA256, //1027
						tls.ECDSAWithP384AndSHA384, //1283
						tls.ECDSAWithP521AndSHA512, //1539
						tls.Ed25519,                // 2055
						2056,
						tls.PSSWithSHA256, //2052
						tls.PSSWithSHA384, //2053
						tls.PSSWithSHA512, //2054
						2057,
						2058,
						2059,
						1025,
						1281,
						1537,
						1026,
						771,
						769,
						770,
						515,
						513,
						514,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{ //43 ,supported_versions
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{ //45  ,psk_key_exchange_modes
						tls.PskModeDHE,
					}},

					&tls.UtlsGREASEExtension{},           //2570 , GREASE
					&tls.ExtendedMasterSecretExtension{}, //23 ,extended_master_secret
					&tls.RenegotiationInfoExtension{ //65281 , renegotiation_info
						Renegotiation: tls.RenegotiateOnceAsClient,
					},

					&tls.SessionTicketExtension{}, // 35  ,session_ticket

					&tls.SCTExtension{}, //18 ,signed_certificate_timestamp
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{ //51 ,key_share
						{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: tls.X25519},
					}},

					&tls.SupportedVersionsExtension{Versions: []uint16{ //43 ,supported_versions
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.SignatureAlgorithmsCertExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							1027, 1283, 1539, 2055, 2056, 2052, 2053, 2054, 2057, 2058, 2059, 1025, 1281, 1537, 1026, 771, 769, 770, 515, 513, 514,
						},
					}, //50
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{ //51 ,key_share
						{Group: tls.X25519},
						{Group: 23},
					}},
					&tls.RenegotiationInfoExtension{ //65281 , renegotiation_info
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 4194304,
		http2.SettingMaxHeaderListSize: 10485760,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 1073741824,
	headerPriority: &http2.PriorityParam{},
}
