const xmlEscape = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&apos;");

const decodeXmlEntities = (value: string): string =>
  value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .trim();

const readTagValue = (xml: string, tagLocalName: string): string | null => {
  const pattern = new RegExp(
    `<(?:[a-zA-Z0-9_]+:)?${tagLocalName}\\b[^>]*>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_]+:)?${tagLocalName}>`,
    "i"
  );
  const match = pattern.exec(xml);
  if (!match) {
    return null;
  }
  return decodeXmlEntities(match[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1"));
};

const readOpenTagAttributes = (xml: string, tagLocalName: string): Record<string, string> => {
  const openTagPattern = new RegExp(`<(?:[a-zA-Z0-9_]+:)?${tagLocalName}\\b([^>]*)>`, "i");
  const openTagMatch = openTagPattern.exec(xml);
  if (!openTagMatch) {
    return {};
  }
  const rawAttributes = openTagMatch[1] || "";
  const map: Record<string, string> = {};
  const regex = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*=\s*"([^"]*)"/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(rawAttributes)) !== null) {
    map[match[1]] = decodeXmlEntities(match[2]);
  }
  return map;
};

const normalizeIsoLike = (value: string | null): string | null => {
  if (!value) {
    return null;
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return null;
  }
  return new Date(parsed).toISOString();
};

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

const base64ToBytes = (value: string): Uint8Array => {
  const normalized = value.replace(/\s+/g, "");
  const decoded = atob(normalized);
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  return bytes;
};

type Asn1Node = {
  tag: number;
  headerLength: number;
  length: number;
  start: number;
  valueStart: number;
  end: number;
};

const readAsn1Node = (bytes: Uint8Array, offset: number): Asn1Node => {
  if (offset >= bytes.length) {
    throw new Error("ASN.1 parse error: offset out of bounds");
  }
  const tag = bytes[offset];
  let lengthByteIndex = offset + 1;
  if (lengthByteIndex >= bytes.length) {
    throw new Error("ASN.1 parse error: missing length");
  }
  const firstLengthByte = bytes[lengthByteIndex];
  let length = 0;
  let headerLength = 2;
  if ((firstLengthByte & 0x80) === 0) {
    length = firstLengthByte;
  } else {
    const count = firstLengthByte & 0x7f;
    if (count < 1 || count > 4) {
      throw new Error("ASN.1 parse error: unsupported length encoding");
    }
    headerLength = 2 + count;
    lengthByteIndex += 1;
    if (lengthByteIndex + count > bytes.length) {
      throw new Error("ASN.1 parse error: length exceeds buffer");
    }
    for (let index = 0; index < count; index += 1) {
      length = (length << 8) | bytes[lengthByteIndex + index];
    }
  }

  const start = offset;
  const valueStart = offset + headerLength;
  const end = valueStart + length;
  if (end > bytes.length) {
    throw new Error("ASN.1 parse error: node exceeds buffer");
  }
  return {
    tag,
    headerLength,
    length,
    start,
    valueStart,
    end
  };
};

const readAsn1Children = (bytes: Uint8Array, parent: Asn1Node): Asn1Node[] => {
  const children: Asn1Node[] = [];
  let cursor = parent.valueStart;
  while (cursor < parent.end) {
    const child = readAsn1Node(bytes, cursor);
    children.push(child);
    cursor = child.end;
  }
  if (cursor !== parent.end) {
    throw new Error("ASN.1 parse error: child parsing misaligned");
  }
  return children;
};

const extractSpkiFromX509Certificate = (certificateDer: Uint8Array): Uint8Array => {
  const root = readAsn1Node(certificateDer, 0);
  if (root.tag !== 0x30) {
    throw new Error("X.509 parse error: certificate root is not SEQUENCE");
  }
  const rootChildren = readAsn1Children(certificateDer, root);
  if (rootChildren.length < 1) {
    throw new Error("X.509 parse error: missing TBSCertificate");
  }
  const tbsCertificate = rootChildren[0];
  if (tbsCertificate.tag !== 0x30) {
    throw new Error("X.509 parse error: TBSCertificate is not SEQUENCE");
  }
  const tbsChildren = readAsn1Children(certificateDer, tbsCertificate);
  if (tbsChildren.length < 6) {
    throw new Error("X.509 parse error: TBSCertificate is truncated");
  }

  let index = 0;
  if (tbsChildren[0].tag === 0xa0) {
    index = 1;
  }
  const spkiIndex = index + 5;
  const spkiNode = tbsChildren[spkiIndex];
  if (!spkiNode || spkiNode.tag !== 0x30) {
    throw new Error("X.509 parse error: SubjectPublicKeyInfo not found");
  }
  return certificateDer.slice(spkiNode.start, spkiNode.end);
};

export type SamlXmlSignatureValidationMode = "off" | "optional" | "required";

export type SamlXmlSignatureVerification = {
  mode: SamlXmlSignatureValidationMode;
  attempted: boolean;
  verified: boolean;
  signatureAlgorithm: string | null;
  canonicalizationAlgorithm: string | null;
  reason: string | null;
};

export type SamlParsedResponse = {
  issuer: string | null;
  assertionIssuer: string | null;
  nameId: string | null;
  destination: string | null;
  inResponseTo: string | null;
  audience: string | null;
  notBefore: string | null;
  notOnOrAfter: string | null;
  signaturePresent: boolean;
  embeddedCertificates: string[];
  attributes: Record<string, string[]>;
  rawXml: string;
};

export const normalizePemCertificate = (value: string): string =>
  value
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
    .trim();

const extractSignatureBlock = (xml: string): string | null => {
  const match = /<(?:[a-zA-Z0-9_]+:)?Signature\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Signature>/i.exec(xml);
  return match?.[0] ?? null;
};

const extractSignedInfo = (signatureXml: string): string | null => {
  const match =
    /<(?:[a-zA-Z0-9_]+:)?SignedInfo\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?SignedInfo>/i.exec(signatureXml);
  return match?.[0] ?? null;
};

const canonicalizeSignedInfo = (signedInfoXml: string): string =>
  signedInfoXml
    .replace(/^\s*<\?xml[^>]*\?>\s*/i, "")
    .replace(/>\s+</g, "><")
    .trim();

const resolveSignatureImportAlgorithm = (signatureMethodAlgorithm: string | null): {
  algorithm: RsaHashedImportParams;
  uri: string | null;
} | null => {
  const uri = signatureMethodAlgorithm?.trim() || null;
  if (!uri) {
    return null;
  }

  const uriLower = uri.toLowerCase();
  if (uriLower === "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") {
    return {
      algorithm: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      uri
    };
  }
  if (uriLower === "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") {
    return {
      algorithm: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-384"
      },
      uri
    };
  }
  if (uriLower === "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") {
    return {
      algorithm: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-512"
      },
      uri
    };
  }
  if (uriLower === "http://www.w3.org/2000/09/xmldsig#rsa-sha1") {
    return {
      algorithm: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-1"
      },
      uri
    };
  }

  return null;
};

export const verifySamlXmlSignature = async (params: {
  xml: string;
  certificatePem: string;
  mode: SamlXmlSignatureValidationMode;
}): Promise<SamlXmlSignatureVerification> => {
  if (params.mode === "off") {
    return {
      mode: params.mode,
      attempted: false,
      verified: false,
      signatureAlgorithm: null,
      canonicalizationAlgorithm: null,
      reason: "XML signature verification is disabled"
    };
  }

  const signatureXml = extractSignatureBlock(params.xml);
  if (!signatureXml) {
    return {
      mode: params.mode,
      attempted: true,
      verified: false,
      signatureAlgorithm: null,
      canonicalizationAlgorithm: null,
      reason: "Signature block is missing"
    };
  }

  const signedInfoXml = extractSignedInfo(signatureXml);
  const signatureValue = readTagValue(signatureXml, "SignatureValue")?.replace(/\s+/g, "") ?? null;
  const signatureMethodAlgorithm = readOpenTagAttributes(signatureXml, "SignatureMethod").Algorithm ?? null;
  const canonicalizationAlgorithm = readOpenTagAttributes(signatureXml, "CanonicalizationMethod").Algorithm ?? null;

  if (!signedInfoXml || !signatureValue) {
    return {
      mode: params.mode,
      attempted: true,
      verified: false,
      signatureAlgorithm: signatureMethodAlgorithm,
      canonicalizationAlgorithm,
      reason: "SignedInfo or SignatureValue is missing"
    };
  }

  const resolvedAlgorithm = resolveSignatureImportAlgorithm(signatureMethodAlgorithm);
  if (!resolvedAlgorithm) {
    return {
      mode: params.mode,
      attempted: true,
      verified: false,
      signatureAlgorithm: signatureMethodAlgorithm,
      canonicalizationAlgorithm,
      reason: "Unsupported SAML signature algorithm"
    };
  }

  const normalizedCert = normalizePemCertificate(params.certificatePem);
  if (!normalizedCert) {
    return {
      mode: params.mode,
      attempted: true,
      verified: false,
      signatureAlgorithm: resolvedAlgorithm.uri,
      canonicalizationAlgorithm,
      reason: "Configured certificate is empty or invalid"
    };
  }

  try {
    const certificateDer = base64ToBytes(normalizedCert);
    const spki = extractSpkiFromX509Certificate(certificateDer);
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      toArrayBuffer(spki),
      resolvedAlgorithm.algorithm,
      false,
      ["verify"]
    );
    const canonicalSignedInfo = canonicalizeSignedInfo(signedInfoXml);
    const isVerified = await crypto.subtle.verify(
      resolvedAlgorithm.algorithm,
      cryptoKey,
      toArrayBuffer(base64ToBytes(signatureValue)),
      toArrayBuffer(new TextEncoder().encode(canonicalSignedInfo))
    );
    return {
      mode: params.mode,
      attempted: true,
      verified: isVerified,
      signatureAlgorithm: resolvedAlgorithm.uri,
      canonicalizationAlgorithm,
      reason: isVerified ? null : "Signature verification failed"
    };
  } catch (error) {
    return {
      mode: params.mode,
      attempted: true,
      verified: false,
      signatureAlgorithm: resolvedAlgorithm.uri,
      canonicalizationAlgorithm,
      reason: error instanceof Error ? error.message : "Signature verification failed unexpectedly"
    };
  }
};

export const buildSamlSpMetadataXml = (params: {
  entityId: string;
  acsUrl: string;
  wantAssertionsSigned: boolean;
}): string => {
  const entityId = xmlEscape(params.entityId.trim());
  const acsUrl = xmlEscape(params.acsUrl.trim());
  const wantAssertionsSigned = params.wantAssertionsSigned ? "true" : "false";
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}">
  <md:SPSSODescriptor
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="false"
    WantAssertionsSigned="${wantAssertionsSigned}">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="0"
      isDefault="true" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
};

export const buildSamlAuthnRequestXml = (params: {
  id: string;
  issueInstant: string;
  destination: string;
  assertionConsumerServiceUrl: string;
  issuer: string;
}): string => {
  const issueInstant = new Date(Date.parse(params.issueInstant)).toISOString();
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${xmlEscape(params.id)}"
  Version="2.0"
  IssueInstant="${xmlEscape(issueInstant)}"
  Destination="${xmlEscape(params.destination)}"
  AssertionConsumerServiceURL="${xmlEscape(params.assertionConsumerServiceUrl)}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${xmlEscape(params.issuer)}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
</samlp:AuthnRequest>`;
};

export const encodeSamlXmlToBase64 = (xml: string): string => {
  const bytes = new TextEncoder().encode(xml);
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
};

export const decodeSamlBase64Xml = (encoded: string): string => {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new TextDecoder().decode(bytes);
};

export const parseSamlResponseXml = (xml: string): SamlParsedResponse => {
  const attributes: Record<string, string[]> = {};
  const attributeRegex =
    /<(?:[a-zA-Z0-9_]+:)?Attribute\b[^>]*Name="([^"]+)"[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?Attribute>/gi;
  let attributeMatch: RegExpExecArray | null;
  while ((attributeMatch = attributeRegex.exec(xml)) !== null) {
    const key = decodeXmlEntities(attributeMatch[1]);
    const values: string[] = [];
    const valueRegex =
      /<(?:[a-zA-Z0-9_]+:)?AttributeValue\b[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?AttributeValue>/gi;
    let valueMatch: RegExpExecArray | null;
    while ((valueMatch = valueRegex.exec(attributeMatch[2])) !== null) {
      const normalized = decodeXmlEntities(valueMatch[1]);
      if (normalized) {
        values.push(normalized);
      }
    }
    if (values.length > 0) {
      attributes[key] = values;
    }
  }

  const certMatches = xml.match(/<(?:[a-zA-Z0-9_]+:)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?X509Certificate>/gi);
  const embeddedCertificates =
    certMatches?.map((match) => {
      const value = match.replace(/<[^>]+>/g, "");
      return normalizePemCertificate(value);
    }) ?? [];

  const responseAttributes = readOpenTagAttributes(xml, "Response");
  const confirmationAttributes = readOpenTagAttributes(xml, "SubjectConfirmationData");
  const conditionsAttributes = readOpenTagAttributes(xml, "Conditions");

  return {
    issuer: readTagValue(xml, "Issuer"),
    assertionIssuer: (() => {
      const assertionMatch = /<(?:[a-zA-Z0-9_]+:)?Assertion\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Assertion>/i.exec(xml);
      if (!assertionMatch) {
        return null;
      }
      return readTagValue(assertionMatch[0], "Issuer");
    })(),
    nameId: readTagValue(xml, "NameID"),
    destination: responseAttributes.Destination ?? null,
    inResponseTo: responseAttributes.InResponseTo ?? confirmationAttributes.InResponseTo ?? null,
    audience: readTagValue(xml, "Audience"),
    notBefore: normalizeIsoLike(conditionsAttributes.NotBefore ?? null),
    notOnOrAfter: normalizeIsoLike(
      confirmationAttributes.NotOnOrAfter ?? conditionsAttributes.NotOnOrAfter ?? null
    ),
    signaturePresent: /<(?:[a-zA-Z0-9_]+:)?Signature\b/.test(xml),
    embeddedCertificates,
    attributes,
    rawXml: xml
  };
};

export const validateParsedSamlResponse = (params: {
  parsed: SamlParsedResponse;
  idpEntityId: string;
  spEntityId: string;
  acsUrl: string;
  requireSignedAssertions: boolean;
  certificatePem: string;
  expectedInResponseTo?: string | null;
  allowIdpInitiated: boolean;
  clockSkewSeconds?: number;
  signatureValidationMode?: SamlXmlSignatureValidationMode;
  signatureVerification?: SamlXmlSignatureVerification | null;
}): { ok: true; warnings: string[] } | { ok: false; errors: string[] } => {
  const errors: string[] = [];
  const warnings: string[] = [];
  const skewMs = (params.clockSkewSeconds ?? 120) * 1000;

  const issuer = params.parsed.assertionIssuer || params.parsed.issuer;
  if (!issuer || issuer !== params.idpEntityId.trim()) {
    errors.push("SAML issuer does not match configured IdP entity ID");
  }

  if (params.parsed.destination && params.parsed.destination !== params.acsUrl.trim()) {
    errors.push("SAML destination does not match configured ACS URL");
  }

  if (params.parsed.audience && params.parsed.audience !== params.spEntityId.trim()) {
    errors.push("SAML audience does not match configured SP entity ID");
  }

  if (params.expectedInResponseTo) {
    const inResponseTo = params.parsed.inResponseTo?.trim() ?? null;
    if (
      inResponseTo &&
      inResponseTo !== params.expectedInResponseTo &&
      inResponseTo !== `_${params.expectedInResponseTo}`
    ) {
      errors.push("SAML InResponseTo does not match request state");
    }
  } else if (!params.allowIdpInitiated) {
    errors.push("IdP-initiated SAML is disabled for this connection");
  }

  const now = Date.now();
  if (params.parsed.notBefore) {
    const notBeforeTs = Date.parse(params.parsed.notBefore);
    if (!Number.isNaN(notBeforeTs) && now + skewMs < notBeforeTs) {
      errors.push("SAML assertion is not yet valid");
    }
  }
  if (params.parsed.notOnOrAfter) {
    const notOnOrAfterTs = Date.parse(params.parsed.notOnOrAfter);
    if (!Number.isNaN(notOnOrAfterTs) && now - skewMs >= notOnOrAfterTs) {
      errors.push("SAML assertion has expired");
    }
  }

  if (params.requireSignedAssertions) {
    if (!params.parsed.signaturePresent) {
      errors.push("SAML signature is required but missing");
    }
    const expectedCert = normalizePemCertificate(params.certificatePem);
    if (!expectedCert) {
      errors.push("Configured SAML certificate is invalid");
    } else if (!params.parsed.embeddedCertificates.some((value) => value === expectedCert)) {
      errors.push("SAML embedded certificate does not match configured certificate");
    }

    const mode = params.signatureValidationMode ?? "optional";
    const signatureVerification = params.signatureVerification;
    if (mode === "required") {
      if (!signatureVerification?.verified) {
        errors.push(
          `SAML XML signature cryptographic verification failed${
            signatureVerification?.reason ? `: ${signatureVerification.reason}` : ""
          }`
        );
      }
    } else if (
      mode === "optional" &&
      signatureVerification?.attempted &&
      !signatureVerification.verified &&
      signatureVerification.reason
    ) {
      warnings.push(`SAML XML signature was not cryptographically verified: ${signatureVerification.reason}`);
    }
  }

  if (!params.parsed.nameId) {
    errors.push("SAML NameID is missing");
  }

  if (errors.length > 0) {
    return {
      ok: false,
      errors
    };
  }

  return {
    ok: true,
    warnings
  };
};

export const pickSamlAttributeValue = (parsed: SamlParsedResponse, candidates: string[]): string | null => {
  for (const candidate of candidates) {
    const values = parsed.attributes[candidate];
    if (values && values.length > 0) {
      return values[0];
    }
  }
  return null;
};
