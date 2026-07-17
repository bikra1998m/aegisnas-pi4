const base64URLToBuffer = (value: string): ArrayBuffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

const bufferToBase64URL = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window
    .btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
};

export const browserSupportsWebAuthn = (): boolean =>
  typeof window !== 'undefined' &&
  Boolean(window.PublicKeyCredential) &&
  Boolean(navigator.credentials);

export const preparePublicKeyCreationOptions = (publicKey: any): PublicKeyCredentialCreationOptions => ({
  ...publicKey,
  challenge: base64URLToBuffer(publicKey.challenge),
  user: {
    ...publicKey.user,
    id: base64URLToBuffer(publicKey.user.id),
  },
  excludeCredentials: (publicKey.excludeCredentials || []).map((credential: any) => ({
    ...credential,
    id: base64URLToBuffer(credential.id),
  })),
});

export const preparePublicKeyRequestOptions = (publicKey: any): PublicKeyCredentialRequestOptions => ({
  ...publicKey,
  challenge: base64URLToBuffer(publicKey.challenge),
  allowCredentials: (publicKey.allowCredentials || []).map((credential: any) => ({
    ...credential,
    id: base64URLToBuffer(credential.id),
  })),
});

export const publicKeyCredentialToJSON = (credential: Credential | null): any => {
  if (!credential) {
    throw new Error('No passkey credential was returned by the browser.');
  }
  const item = credential as PublicKeyCredential;
  const response = item.response as any;
  const payload: any = {
    id: item.id,
    rawId: bufferToBase64URL(item.rawId),
    type: item.type,
    response: {},
  };
  if (response.clientDataJSON) {
    payload.response.clientDataJSON = bufferToBase64URL(response.clientDataJSON);
  }
  if (response.attestationObject) {
    payload.response.attestationObject = bufferToBase64URL(response.attestationObject);
  }
  if (typeof response.getTransports === 'function') {
    payload.response.transports = response.getTransports();
  }
  if (response.authenticatorData) {
    payload.response.authenticatorData = bufferToBase64URL(response.authenticatorData);
  }
  if (response.signature) {
    payload.response.signature = bufferToBase64URL(response.signature);
  }
  if (response.userHandle) {
    payload.response.userHandle = bufferToBase64URL(response.userHandle);
  }
  return payload;
};

export const createPasskeyCredential = async (publicKey: any): Promise<any> => {
  if (!browserSupportsWebAuthn()) {
    throw new Error('This browser does not support passkeys.');
  }
  const credential = await navigator.credentials.create({
    publicKey: preparePublicKeyCreationOptions(publicKey),
  });
  return publicKeyCredentialToJSON(credential);
};

export const getPasskeyCredential = async (publicKey: any): Promise<any> => {
  if (!browserSupportsWebAuthn()) {
    throw new Error('This browser does not support passkeys.');
  }
  const credential = await navigator.credentials.get({
    publicKey: preparePublicKeyRequestOptions(publicKey),
  });
  return publicKeyCredentialToJSON(credential);
};
