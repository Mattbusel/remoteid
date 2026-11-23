//! Resolving a broadcast Operator ID into a displayable operator identity.
//!
//! The Operator ID message carries the operator's registration string. In the
//! EU (ASD-STAN EN 4709-002) that string is the UAS operator registration
//! number, which begins with the registering country's ISO 3166-1 alpha-3
//! code (for example `FIN...` for Finland, `GBR...` for the United Kingdom).
//! This module turns the raw field into something an operator can read at a
//! glance: the country the aircraft's operator registered in, and the
//! registration body on its own.
//!
//! The question it answers for a security operator: *who registered this
//! drone, and where?* The output is a country name plus the clean
//! registration string, ready to show or look up with the issuing authority.
//!
//! It reports only what the bytes state. It does not invent a country for an
//! unknown prefix, and it does not claim the registration is genuine: Remote
//! ID has no authentication, so a registration string can be copied or made
//! up. Use [`crate::trust`] for the spoof verdict; use this for the readout.

/// An Operator ID resolved into its parts.
///
/// Borrows from the source string, so it lives as long as the text it was
/// parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatorIdentity<'a> {
    /// The full registration string, trailing NUL and ASCII whitespace removed.
    pub display: &'a str,
    /// The leading ISO 3166-1 alpha-3 country code, when the string starts
    /// with one that names a real country (EN 4709-002 operator IDs do).
    pub country_code: Option<&'a str>,
    /// The country that code names, for example `"Finland"`.
    pub country: Option<&'static str>,
    /// The registration body: everything after the country code, or the whole
    /// `display` string when no country code was recognised.
    pub registration: &'a str,
}

impl<'a> OperatorIdentity<'a> {
    /// Resolves a registration string.
    ///
    /// Trailing NUL and ASCII whitespace are trimmed. When the first three
    /// characters are ASCII upper case letters that form a known ISO 3166-1
    /// alpha-3 country code, they are split off as [`country_code`] and
    /// resolved to a [`country`] name, and the rest becomes [`registration`].
    /// Otherwise the whole trimmed string is the registration and the country
    /// fields are `None`.
    ///
    /// [`country_code`]: Self::country_code
    /// [`country`]: Self::country
    /// [`registration`]: Self::registration
    pub fn parse(s: &'a str) -> Self {
        let display = s.trim_end_matches(['\0']).trim_end();
        let b = display.as_bytes();
        if b.len() > 3 && b[..3].iter().all(u8::is_ascii_uppercase) {
            if let Some(country) = country_name(&b[..3]) {
                return OperatorIdentity {
                    display,
                    country_code: Some(&display[..3]),
                    country: Some(country),
                    registration: &display[3..],
                };
            }
        }
        OperatorIdentity {
            display,
            country_code: None,
            country: None,
            registration: display,
        }
    }
}

/// The English short name for an ISO 3166-1 alpha-3 country code, or `None`
/// for a code that is not officially assigned. The codes are upper case.
///
/// EN 4709-002 operator registration numbers start with one of these codes.
pub fn country_name(code: &[u8]) -> Option<&'static str> {
    match code {
        b"ABW" => Some("Aruba"),
        b"AFG" => Some("Afghanistan"),
        b"AGO" => Some("Angola"),
        b"AIA" => Some("Anguilla"),
        b"ALA" => Some("Aland Islands"),
        b"ALB" => Some("Albania"),
        b"AND" => Some("Andorra"),
        b"ARE" => Some("United Arab Emirates"),
        b"ARG" => Some("Argentina"),
        b"ARM" => Some("Armenia"),
        b"ASM" => Some("American Samoa"),
        b"ATA" => Some("Antarctica"),
        b"ATF" => Some("French Southern Territories"),
        b"ATG" => Some("Antigua and Barbuda"),
        b"AUS" => Some("Australia"),
        b"AUT" => Some("Austria"),
        b"AZE" => Some("Azerbaijan"),
        b"BDI" => Some("Burundi"),
        b"BEL" => Some("Belgium"),
        b"BEN" => Some("Benin"),
        b"BES" => Some("Bonaire, Sint Eustatius and Saba"),
        b"BFA" => Some("Burkina Faso"),
        b"BGD" => Some("Bangladesh"),
        b"BGR" => Some("Bulgaria"),
        b"BHR" => Some("Bahrain"),
        b"BHS" => Some("Bahamas"),
        b"BIH" => Some("Bosnia and Herzegovina"),
        b"BLM" => Some("Saint Barthelemy"),
        b"BLR" => Some("Belarus"),
        b"BLZ" => Some("Belize"),
        b"BMU" => Some("Bermuda"),
        b"BOL" => Some("Bolivia"),
        b"BRA" => Some("Brazil"),
        b"BRB" => Some("Barbados"),
        b"BRN" => Some("Brunei Darussalam"),
        b"BTN" => Some("Bhutan"),
        b"BVT" => Some("Bouvet Island"),
        b"BWA" => Some("Botswana"),
        b"CAF" => Some("Central African Republic"),
        b"CAN" => Some("Canada"),
        b"CCK" => Some("Cocos (Keeling) Islands"),
        b"CHE" => Some("Switzerland"),
        b"CHL" => Some("Chile"),
        b"CHN" => Some("China"),
        b"CIV" => Some("Cote d'Ivoire"),
        b"CMR" => Some("Cameroon"),
        b"COD" => Some("Congo (Democratic Republic)"),
        b"COG" => Some("Congo"),
        b"COK" => Some("Cook Islands"),
        b"COL" => Some("Colombia"),
        b"COM" => Some("Comoros"),
        b"CPV" => Some("Cabo Verde"),
        b"CRI" => Some("Costa Rica"),
        b"CUB" => Some("Cuba"),
        b"CUW" => Some("Curacao"),
        b"CXR" => Some("Christmas Island"),
        b"CYM" => Some("Cayman Islands"),
        b"CYP" => Some("Cyprus"),
        b"CZE" => Some("Czechia"),
        b"DEU" => Some("Germany"),
        b"DJI" => Some("Djibouti"),
        b"DMA" => Some("Dominica"),
        b"DNK" => Some("Denmark"),
        b"DOM" => Some("Dominican Republic"),
        b"DZA" => Some("Algeria"),
        b"ECU" => Some("Ecuador"),
        b"EGY" => Some("Egypt"),
        b"ERI" => Some("Eritrea"),
        b"ESH" => Some("Western Sahara"),
        b"ESP" => Some("Spain"),
        b"EST" => Some("Estonia"),
        b"ETH" => Some("Ethiopia"),
        b"FIN" => Some("Finland"),
        b"FJI" => Some("Fiji"),
        b"FLK" => Some("Falkland Islands"),
        b"FRA" => Some("France"),
        b"FRO" => Some("Faroe Islands"),
        b"FSM" => Some("Micronesia"),
        b"GAB" => Some("Gabon"),
        b"GBR" => Some("United Kingdom"),
        b"GEO" => Some("Georgia"),
        b"GGY" => Some("Guernsey"),
        b"GHA" => Some("Ghana"),
        b"GIB" => Some("Gibraltar"),
        b"GIN" => Some("Guinea"),
        b"GLP" => Some("Guadeloupe"),
        b"GMB" => Some("Gambia"),
        b"GNB" => Some("Guinea-Bissau"),
        b"GNQ" => Some("Equatorial Guinea"),
        b"GRC" => Some("Greece"),
        b"GRD" => Some("Grenada"),
        b"GRL" => Some("Greenland"),
        b"GTM" => Some("Guatemala"),
        b"GUF" => Some("French Guiana"),
        b"GUM" => Some("Guam"),
        b"GUY" => Some("Guyana"),
        b"HKG" => Some("Hong Kong"),
        b"HMD" => Some("Heard Island and McDonald Islands"),
        b"HND" => Some("Honduras"),
        b"HRV" => Some("Croatia"),
        b"HTI" => Some("Haiti"),
        b"HUN" => Some("Hungary"),
        b"IDN" => Some("Indonesia"),
        b"IMN" => Some("Isle of Man"),
        b"IND" => Some("India"),
        b"IOT" => Some("British Indian Ocean Territory"),
        b"IRL" => Some("Ireland"),
        b"IRN" => Some("Iran"),
        b"IRQ" => Some("Iraq"),
        b"ISL" => Some("Iceland"),
        b"ISR" => Some("Israel"),
        b"ITA" => Some("Italy"),
        b"JAM" => Some("Jamaica"),
        b"JEY" => Some("Jersey"),
        b"JOR" => Some("Jordan"),
        b"JPN" => Some("Japan"),
        b"KAZ" => Some("Kazakhstan"),
        b"KEN" => Some("Kenya"),
        b"KGZ" => Some("Kyrgyzstan"),
        b"KHM" => Some("Cambodia"),
        b"KIR" => Some("Kiribati"),
        b"KNA" => Some("Saint Kitts and Nevis"),
        b"KOR" => Some("South Korea"),
        b"KWT" => Some("Kuwait"),
        b"LAO" => Some("Laos"),
        b"LBN" => Some("Lebanon"),
        b"LBR" => Some("Liberia"),
        b"LBY" => Some("Libya"),
        b"LCA" => Some("Saint Lucia"),
        b"LIE" => Some("Liechtenstein"),
        b"LKA" => Some("Sri Lanka"),
        b"LSO" => Some("Lesotho"),
        b"LTU" => Some("Lithuania"),
        b"LUX" => Some("Luxembourg"),
        b"LVA" => Some("Latvia"),
        b"MAC" => Some("Macao"),
        b"MAF" => Some("Saint Martin"),
        b"MAR" => Some("Morocco"),
        b"MCO" => Some("Monaco"),
        b"MDA" => Some("Moldova"),
        b"MDG" => Some("Madagascar"),
        b"MDV" => Some("Maldives"),
        b"MEX" => Some("Mexico"),
        b"MHL" => Some("Marshall Islands"),
        b"MKD" => Some("North Macedonia"),
        b"MLI" => Some("Mali"),
        b"MLT" => Some("Malta"),
        b"MMR" => Some("Myanmar"),
        b"MNE" => Some("Montenegro"),
        b"MNG" => Some("Mongolia"),
        b"MNP" => Some("Northern Mariana Islands"),
        b"MOZ" => Some("Mozambique"),
        b"MRT" => Some("Mauritania"),
        b"MSR" => Some("Montserrat"),
        b"MTQ" => Some("Martinique"),
        b"MUS" => Some("Mauritius"),
        b"MWI" => Some("Malawi"),
        b"MYS" => Some("Malaysia"),
        b"MYT" => Some("Mayotte"),
        b"NAM" => Some("Namibia"),
        b"NCL" => Some("New Caledonia"),
        b"NER" => Some("Niger"),
        b"NFK" => Some("Norfolk Island"),
        b"NGA" => Some("Nigeria"),
        b"NIC" => Some("Nicaragua"),
        b"NIU" => Some("Niue"),
        b"NLD" => Some("Netherlands"),
        b"NOR" => Some("Norway"),
        b"NPL" => Some("Nepal"),
        b"NRU" => Some("Nauru"),
        b"NZL" => Some("New Zealand"),
        b"OMN" => Some("Oman"),
        b"PAK" => Some("Pakistan"),
        b"PAN" => Some("Panama"),
        b"PCN" => Some("Pitcairn"),
        b"PER" => Some("Peru"),
        b"PHL" => Some("Philippines"),
        b"PLW" => Some("Palau"),
        b"PNG" => Some("Papua New Guinea"),
        b"POL" => Some("Poland"),
        b"PRI" => Some("Puerto Rico"),
        b"PRK" => Some("North Korea"),
        b"PRT" => Some("Portugal"),
        b"PRY" => Some("Paraguay"),
        b"PSE" => Some("Palestine"),
        b"PYF" => Some("French Polynesia"),
        b"QAT" => Some("Qatar"),
        b"REU" => Some("Reunion"),
        b"ROU" => Some("Romania"),
        b"RUS" => Some("Russia"),
        b"RWA" => Some("Rwanda"),
        b"SAU" => Some("Saudi Arabia"),
        b"SDN" => Some("Sudan"),
        b"SEN" => Some("Senegal"),
        b"SGP" => Some("Singapore"),
        b"SGS" => Some("South Georgia and the South Sandwich Islands"),
        b"SHN" => Some("Saint Helena"),
        b"SJM" => Some("Svalbard and Jan Mayen"),
        b"SLB" => Some("Solomon Islands"),
        b"SLE" => Some("Sierra Leone"),
        b"SLV" => Some("El Salvador"),
        b"SMR" => Some("San Marino"),
        b"SOM" => Some("Somalia"),
        b"SPM" => Some("Saint Pierre and Miquelon"),
        b"SRB" => Some("Serbia"),
        b"SSD" => Some("South Sudan"),
        b"STP" => Some("Sao Tome and Principe"),
        b"SUR" => Some("Suriname"),
        b"SVK" => Some("Slovakia"),
        b"SVN" => Some("Slovenia"),
        b"SWE" => Some("Sweden"),
        b"SWZ" => Some("Eswatini"),
        b"SXM" => Some("Sint Maarten"),
        b"SYC" => Some("Seychelles"),
        b"SYR" => Some("Syria"),
        b"TCA" => Some("Turks and Caicos Islands"),
        b"TCD" => Some("Chad"),
        b"TGO" => Some("Togo"),
        b"THA" => Some("Thailand"),
        b"TJK" => Some("Tajikistan"),
        b"TKL" => Some("Tokelau"),
        b"TKM" => Some("Turkmenistan"),
        b"TLS" => Some("Timor-Leste"),
        b"TON" => Some("Tonga"),
        b"TTO" => Some("Trinidad and Tobago"),
        b"TUN" => Some("Tunisia"),
        b"TUR" => Some("Turkey"),
        b"TUV" => Some("Tuvalu"),
        b"TWN" => Some("Taiwan"),
        b"TZA" => Some("Tanzania"),
        b"UGA" => Some("Uganda"),
        b"UKR" => Some("Ukraine"),
        b"UMI" => Some("United States Minor Outlying Islands"),
        b"URY" => Some("Uruguay"),
        b"USA" => Some("United States"),
        b"UZB" => Some("Uzbekistan"),
        b"VAT" => Some("Holy See"),
        b"VCT" => Some("Saint Vincent and the Grenadines"),
        b"VEN" => Some("Venezuela"),
        b"VGB" => Some("British Virgin Islands"),
        b"VIR" => Some("US Virgin Islands"),
        b"VNM" => Some("Vietnam"),
        b"VUT" => Some("Vanuatu"),
        b"WLF" => Some("Wallis and Futuna"),
        b"WSM" => Some("Samoa"),
        b"YEM" => Some("Yemen"),
        b"ZAF" => Some("South Africa"),
        b"ZMB" => Some("Zambia"),
        b"ZWE" => Some("Zimbabwe"),
        _ => None,
    }
}
